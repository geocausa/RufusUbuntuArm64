package ffu

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	ffuTrustMetadataSchema        = 1
	ffuTrustMetadataPurpose       = "ffu-trust-bundle-metadata"
	ffuTrustMetadataAlgorithm     = "ed25519"
	maxFFUTrustMetadataBytes      = 256 << 10
	maxFFUTrustMetadataKeys       = 32
	maxFFUTrustMetadataSignatures = 64
	maxFFUTrustMetadataLifetime   = 366 * 24 * time.Hour
)

// TrustMetadataKey is one explicitly provisioned public key. Production code
// has no built-in policy or private signing key; callers must supply the full
// reviewed key set for every authentication attempt.
type TrustMetadataKey struct {
	ID              string `json:"id"`
	Algorithm       string `json:"algorithm"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

// TrustMetadataPolicy is the caller-provisioned authorization boundary for
// trust-bundle metadata. Its deterministic digest is signed into each payload.
type TrustMetadataPolicy struct {
	Version   uint64             `json:"version"`
	Threshold int                `json:"threshold"`
	Keys      []TrustMetadataKey `json:"keys"`
}

// TrustMetadataDocument is the exact canonical payload covered by signatures.
// It binds one policy version and digest to the exact inactive trust-bundle
// bytes, sequence, size, and validity window.
type TrustMetadataDocument struct {
	Schema        int    `json:"schema"`
	Purpose       string `json:"purpose"`
	Sequence      uint64 `json:"sequence"`
	KeySetVersion uint64 `json:"key_set_version"`
	KeySetSHA256  string `json:"key_set_sha256"`
	Threshold     int    `json:"threshold"`
	GeneratedAt   string `json:"generated_at"`
	ExpiresAt     string `json:"expires_at"`
	BundleSize    uint64 `json:"bundle_size"`
	BundleSHA256  string `json:"bundle_sha256"`
}

// TrustMetadataSignature identifies the authorized public key and exact
// signature algorithm used for one signature over the canonical signed bytes.
type TrustMetadataSignature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// TrustMetadataEnvelope keeps the exact signed bytes separate from signatures.
type TrustMetadataEnvelope struct {
	Signed     json.RawMessage          `json:"signed"`
	Signatures []TrustMetadataSignature `json:"signatures"`
}

// TrustMetadataRollbackState is caller-supplied persistent evidence. This
// read-only tranche never writes, publishes, or updates it.
type TrustMetadataRollbackState struct {
	Sequence     uint64 `json:"sequence"`
	BundleSHA256 string `json:"bundle_sha256"`
}

// TrustBundleAuthentication records a successful threshold check. It does not
// activate roots, build a chain, trust a publisher, or mutate durable state.
type TrustBundleAuthentication struct {
	Schema         int      `json:"schema"`
	Purpose        string   `json:"purpose"`
	Sequence       uint64   `json:"sequence"`
	KeySetVersion  uint64   `json:"key_set_version"`
	KeySetSHA256   string   `json:"key_set_sha256"`
	Threshold      int      `json:"threshold"`
	SigningKeyIDs  []string `json:"signing_key_ids"`
	GeneratedAt    string   `json:"generated_at"`
	ExpiresAt      string   `json:"expires_at"`
	EvaluationTime string   `json:"evaluation_time"`
	BundleSize     uint64   `json:"bundle_size"`
	BundleSHA256   string   `json:"bundle_sha256"`
	MetadataSHA256 string   `json:"metadata_sha256"`
}

type verifiedTrustMetadataPolicy struct {
	version   uint64
	threshold int
	sha256    string
	keys      map[string]ed25519.PublicKey
}

// AuthenticateTrustBundleMetadata verifies a strict threshold-signed envelope
// against caller-provisioned public keys and the exact trust-bundle bytes. The
// returned plan remains inactive and read-only.
func AuthenticateTrustBundleMetadata(bundleData, envelopeData []byte, policy TrustMetadataPolicy, previous TrustMetadataRollbackState, evaluationTime time.Time) (TrustBundlePlan, error) {
	if evaluationTime.IsZero() {
		return TrustBundlePlan{}, errors.New("FFU trust-metadata evaluation time is zero")
	}
	if len(envelopeData) == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust metadata is empty")
	}
	if len(envelopeData) > maxFFUTrustMetadataBytes {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust metadata exceeds %d-byte limit", maxFFUTrustMetadataBytes)
	}
	verifiedPolicy, err := verifyTrustMetadataPolicy(policy)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	previousDigest, err := validateTrustMetadataRollbackState(previous)
	if err != nil {
		return TrustBundlePlan{}, err
	}

	envelope, document, canonical, err := parseTrustMetadataEnvelope(envelopeData)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	generatedAt, expiresAt, err := validateTrustMetadataDocument(document, verifiedPolicy, evaluationTime)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if len(bundleData) == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust bundle is empty")
	}
	if int64(len(bundleData)) > maxFFUTrustBundleBytes {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle exceeds %d-byte limit", maxFFUTrustBundleBytes)
	}
	if document.BundleSize != uint64(len(bundleData)) {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust-metadata bundle size %d does not match %d bytes", document.BundleSize, len(bundleData))
	}
	providedDigest, _ := hex.DecodeString(document.BundleSHA256)
	calculatedDigest := sha256.Sum256(bundleData)
	if subtle.ConstantTimeCompare(providedDigest, calculatedDigest[:]) != 1 {
		return TrustBundlePlan{}, errors.New("FFU trust-metadata bundle SHA-256 does not match the selected bundle bytes")
	}

	signingKeyIDs, err := verifyTrustMetadataSignatures(envelope.Signatures, verifiedPolicy, canonical)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if previous.Sequence > document.Sequence {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust-metadata sequence %d is below rollback state %d", document.Sequence, previous.Sequence)
	}
	if previous.Sequence == document.Sequence && previous.Sequence != 0 && subtle.ConstantTimeCompare(previousDigest, calculatedDigest[:]) != 1 {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust-metadata sequence %d reuses a different bundle SHA-256", document.Sequence)
	}

	bundlePlan, err := ParseTrustBundleBytes(bundleData, previous.Sequence, evaluationTime)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if document.Sequence != bundlePlan.Sequence {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust-metadata sequence %d does not match bundle sequence %d", document.Sequence, bundlePlan.Sequence)
	}
	if bundlePlan.BundleSHA256 != document.BundleSHA256 {
		return TrustBundlePlan{}, errors.New("FFU trust-metadata bundle digest changed during structural validation")
	}

	metadataDigest := sha256.Sum256(canonical)
	bundlePlan.BundleSignatureAuthenticated = true
	bundlePlan.Authentication = &TrustBundleAuthentication{
		Schema:         document.Schema,
		Purpose:        document.Purpose,
		Sequence:       document.Sequence,
		KeySetVersion:  document.KeySetVersion,
		KeySetSHA256:   document.KeySetSHA256,
		Threshold:      document.Threshold,
		SigningKeyIDs:  append([]string(nil), signingKeyIDs...),
		GeneratedAt:    generatedAt.Format(time.RFC3339),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		EvaluationTime: evaluationTime.UTC().Format(time.RFC3339),
		BundleSize:     document.BundleSize,
		BundleSHA256:   document.BundleSHA256,
		MetadataSHA256: hex.EncodeToString(metadataDigest[:]),
	}
	bundlePlan.TrustAnchorsActivated = false
	bundlePlan.CertificateChainBuilt = false
	bundlePlan.PublisherTrusted = false
	bundlePlan.Limitations = []string{
		"the exact bundle bytes were threshold-authenticated against caller-provisioned metadata keys",
		"trust anchors remain inactive until rollback state and durable no-replace publication complete in a separate transaction",
		"the host TLS certificate store is never treated as an Authenticode policy source",
		"no certificate chain, publisher decision, target binding, network request, durable state mutation, or executor is performed",
	}
	bundlePlan.PlanSHA256 = trustBundlePlanDigest(bundlePlan)
	return bundlePlan, nil
}

func verifyTrustMetadataPolicy(policy TrustMetadataPolicy) (verifiedTrustMetadataPolicy, error) {
	if policy.Version == 0 {
		return verifiedTrustMetadataPolicy{}, errors.New("FFU trust-metadata key-set version must be non-zero")
	}
	if len(policy.Keys) == 0 || len(policy.Keys) > maxFFUTrustMetadataKeys {
		return verifiedTrustMetadataPolicy{}, fmt.Errorf("FFU trust-metadata policy must contain between 1 and %d keys", maxFFUTrustMetadataKeys)
	}
	if policy.Threshold <= 0 || policy.Threshold > len(policy.Keys) {
		return verifiedTrustMetadataPolicy{}, errors.New("FFU trust-metadata policy threshold is invalid")
	}
	keys := make(map[string]ed25519.PublicKey, len(policy.Keys))
	previous := ""
	for index, key := range policy.Keys {
		if key.Algorithm != ffuTrustMetadataAlgorithm {
			return verifiedTrustMetadataPolicy{}, fmt.Errorf("FFU trust-metadata key %d uses unsupported algorithm %q", index, key.Algorithm)
		}
		if !canonicalTrustMetadataKeyID(key.ID) {
			return verifiedTrustMetadataPolicy{}, fmt.Errorf("FFU trust-metadata key %d has invalid id %q", index, key.ID)
		}
		if previous != "" && key.ID <= previous {
			return verifiedTrustMetadataPolicy{}, errors.New("FFU trust-metadata policy keys must be sorted by id")
		}
		previous = key.ID
		publicBytes, err := decodeCanonicalTrustMetadataBase64(
			key.PublicKeyBase64,
			ed25519.PublicKeySize,
			fmt.Sprintf("FFU trust-metadata key %q public key", key.ID),
		)
		if err != nil {
			return verifiedTrustMetadataPolicy{}, err
		}
		publicKey := ed25519.PublicKey(append([]byte(nil), publicBytes...))
		digest := sha256.Sum256(publicKey)
		if key.ID != hex.EncodeToString(digest[:]) {
			return verifiedTrustMetadataPolicy{}, fmt.Errorf("FFU trust-metadata key id %q does not match its public key", key.ID)
		}
		if _, exists := keys[key.ID]; exists {
			return verifiedTrustMetadataPolicy{}, fmt.Errorf("FFU trust-metadata policy repeats key %q", key.ID)
		}
		keys[key.ID] = publicKey
	}
	return verifiedTrustMetadataPolicy{
		version:   policy.Version,
		threshold: policy.Threshold,
		sha256:    trustMetadataPolicyDigest(policy),
		keys:      keys,
	}, nil
}

func parseTrustMetadataEnvelope(data []byte) (TrustMetadataEnvelope, TrustMetadataDocument, []byte, error) {
	if err := rejectDuplicateTrustMetadataJSONMembers(data); err != nil {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope TrustMetadataEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("decode FFU trust-metadata envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, errors.New("FFU trust-metadata envelope contains multiple JSON values")
		}
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("decode trailing FFU trust-metadata envelope data: %w", err)
	}
	if len(envelope.Signed) == 0 {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, errors.New("FFU trust-metadata signed payload is empty")
	}
	if len(envelope.Signatures) == 0 || len(envelope.Signatures) > maxFFUTrustMetadataSignatures {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("FFU trust-metadata envelope must contain between 1 and %d signatures", maxFFUTrustMetadataSignatures)
	}

	signedDecoder := json.NewDecoder(bytes.NewReader(envelope.Signed))
	signedDecoder.DisallowUnknownFields()
	var document TrustMetadataDocument
	if err := signedDecoder.Decode(&document); err != nil {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("decode FFU trust-metadata signed payload: %w", err)
	}
	if err := signedDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, errors.New("FFU trust-metadata signed payload contains multiple JSON values")
		}
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("decode trailing FFU trust-metadata signed payload: %w", err)
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, fmt.Errorf("canonicalize FFU trust-metadata payload: %w", err)
	}
	if !bytes.Equal(envelope.Signed, canonical) {
		return TrustMetadataEnvelope{}, TrustMetadataDocument{}, nil, errors.New("FFU trust-metadata signed payload is not canonical JSON")
	}
	return envelope, document, canonical, nil
}

func rejectDuplicateTrustMetadataJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanTrustMetadataJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("validate FFU trust-metadata JSON members: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("FFU trust-metadata JSON contains multiple values")
		}
		return fmt.Errorf("validate trailing FFU trust-metadata JSON: %w", err)
	}
	return nil
}

func scanTrustMetadataJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("json nesting exceeds 16 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("json object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanTrustMetadataJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("json object has invalid closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := scanTrustMetadataJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("json array has invalid closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateTrustMetadataDocument(document TrustMetadataDocument, policy verifiedTrustMetadataPolicy, evaluationTime time.Time) (time.Time, time.Time, error) {
	if document.Schema != ffuTrustMetadataSchema {
		return time.Time{}, time.Time{}, fmt.Errorf("unsupported FFU trust-metadata schema %d", document.Schema)
	}
	if document.Purpose != ffuTrustMetadataPurpose {
		return time.Time{}, time.Time{}, fmt.Errorf("unsupported FFU trust-metadata purpose %q", document.Purpose)
	}
	if document.Sequence == 0 {
		return time.Time{}, time.Time{}, errors.New("FFU trust-metadata sequence must be non-zero")
	}
	if document.KeySetVersion != policy.version {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust-metadata key-set version %d does not match policy version %d", document.KeySetVersion, policy.version)
	}
	if document.Threshold != policy.threshold {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust-metadata threshold %d does not match policy threshold %d", document.Threshold, policy.threshold)
	}
	if document.KeySetSHA256 != policy.sha256 {
		return time.Time{}, time.Time{}, errors.New("FFU trust-metadata key-set SHA-256 does not match the supplied policy")
	}
	if _, err := canonicalSHA256Fingerprint(document.BundleSHA256, "metadata.bundle_sha256"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if document.BundleSize == 0 || document.BundleSize > uint64(maxFFUTrustBundleBytes) {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust-metadata bundle size %d is outside 1..%d", document.BundleSize, maxFFUTrustBundleBytes)
	}
	generatedAt, err := parseCanonicalTrustMetadataTime(document.GeneratedAt, "generated_at")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := parseCanonicalTrustMetadataTime(document.ExpiresAt, "expires_at")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !expiresAt.After(generatedAt) {
		return time.Time{}, time.Time{}, errors.New("FFU trust-metadata expiry must be after generation time")
	}
	if expiresAt.Sub(generatedAt) > maxFFUTrustMetadataLifetime {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust-metadata lifetime exceeds %s", maxFFUTrustMetadataLifetime)
	}
	evaluationTime = evaluationTime.UTC()
	if evaluationTime.Before(generatedAt) {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust metadata is not valid before %s", generatedAt.Format(time.RFC3339))
	}
	if !evaluationTime.Before(expiresAt) {
		return time.Time{}, time.Time{}, fmt.Errorf("FFU trust metadata expired at %s", expiresAt.Format(time.RFC3339))
	}
	return generatedAt, expiresAt, nil
}

func verifyTrustMetadataSignatures(signatures []TrustMetadataSignature, policy verifiedTrustMetadataPolicy, canonical []byte) ([]string, error) {
	seen := make(map[string]struct{}, len(signatures))
	valid := make([]string, 0, len(signatures))
	previous := ""
	for index, signature := range signatures {
		if signature.Algorithm != ffuTrustMetadataAlgorithm {
			return nil, fmt.Errorf("FFU trust-metadata signature %d uses unsupported algorithm %q", index, signature.Algorithm)
		}
		if !canonicalTrustMetadataKeyID(signature.KeyID) {
			return nil, fmt.Errorf("FFU trust-metadata signature %d has invalid key id %q", index, signature.KeyID)
		}
		if previous != "" && signature.KeyID <= previous {
			if signature.KeyID == previous {
				return nil, fmt.Errorf("FFU trust-metadata envelope repeats signature for key %q", signature.KeyID)
			}
			return nil, errors.New("FFU trust-metadata signatures must be sorted by key id")
		}
		previous = signature.KeyID
		if _, exists := seen[signature.KeyID]; exists {
			return nil, fmt.Errorf("FFU trust-metadata envelope repeats signature for key %q", signature.KeyID)
		}
		seen[signature.KeyID] = struct{}{}
		publicKey, authorized := policy.keys[signature.KeyID]
		if !authorized {
			return nil, fmt.Errorf("FFU trust-metadata signature references unknown key %q", signature.KeyID)
		}
		signatureBytes, err := decodeCanonicalTrustMetadataBase64(
			signature.Signature,
			ed25519.SignatureSize,
			fmt.Sprintf("FFU trust-metadata signature for key %q", signature.KeyID),
		)
		if err != nil {
			return nil, err
		}
		if !ed25519.Verify(publicKey, canonical, signatureBytes) {
			return nil, fmt.Errorf("verify FFU trust-metadata signature for key %q", signature.KeyID)
		}
		valid = append(valid, signature.KeyID)
	}
	if len(valid) < policy.threshold {
		return nil, fmt.Errorf("FFU trust-metadata signature threshold requires %d valid keys, found %d", policy.threshold, len(valid))
	}
	return valid, nil
}

func validateTrustMetadataRollbackState(previous TrustMetadataRollbackState) ([]byte, error) {
	if previous.Sequence == 0 {
		if previous.BundleSHA256 != "" {
			return nil, errors.New("FFU trust-metadata rollback state has a digest without a sequence")
		}
		return nil, nil
	}
	canonical, err := canonicalSHA256Fingerprint(previous.BundleSHA256, "rollback_state.bundle_sha256")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(canonical)
}

func decodeCanonicalTrustMetadataBase64(value string, expectedSize int, label string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedSize {
		return nil, fmt.Errorf("decode %s", label)
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must use canonical padded base64", label)
	}
	return decoded, nil
}

func parseCanonicalTrustMetadataTime(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse FFU trust-metadata %s: %w", field, err)
	}
	parsed = parsed.UTC()
	if value != parsed.Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("FFU trust-metadata %s must use canonical UTC RFC3339", field)
	}
	return parsed, nil
}

func canonicalTrustMetadataKeyID(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func trustMetadataPolicyDigest(policy TrustMetadataPolicy) string {
	digest := sha256.New()
	writeTrustUint64(digest, policy.Version)
	writeTrustUint64(digest, uint64(policy.Threshold))
	writeTrustUint64(digest, uint64(len(policy.Keys)))
	for _, key := range policy.Keys {
		writeTrustString(digest, key.ID)
		writeTrustString(digest, key.Algorithm)
		writeTrustString(digest, key.PublicKeyBase64)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// CanonicalTrustMetadataPolicySHA256 returns the deterministic digest that a
// metadata document must bind. Invalid policies are rejected.
func CanonicalTrustMetadataPolicySHA256(policy TrustMetadataPolicy) (string, error) {
	verified, err := verifyTrustMetadataPolicy(policy)
	if err != nil {
		return "", err
	}
	return verified.sha256, nil
}
