package acquisition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	TrustSchemaVersion        = 1
	MaxRootMetadataBytes      = 256 * 1024
	MaxChannelCatalogBytes    = MaxCatalogBytes
	maxRootMetadataLifetime   = 2 * 366 * 24 * time.Hour
	maxCatalogMetadataLife    = 90 * 24 * time.Hour
	maximumTrustedKeyCount    = 32
	maximumMetadataSignatures = 64
)

// MetadataSignature is an Ed25519 signature over the exact canonical bytes in
// an envelope's signed member.
type MetadataSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// MetadataEnvelope keeps the signed payload separate from its signatures so
// root and catalog roles can share the same strict parser.
type MetadataEnvelope struct {
	Signed     json.RawMessage     `json:"signed"`
	Signatures []MetadataSignature `json:"signatures"`
}

type TrustKey struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Public string `json:"public"`
}

type TrustRole struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type RootRoles struct {
	Root    TrustRole `json:"root"`
	Catalog TrustRole `json:"catalog"`
}

// RootMetadata authorizes both future root metadata and online catalog keys.
type RootMetadata struct {
	Type      string     `json:"_type"`
	Schema    int        `json:"schema"`
	Version   int        `json:"version"`
	Generated string     `json:"generated"`
	Expires   string     `json:"expires"`
	Keys      []TrustKey `json:"keys"`
	Roles     RootRoles  `json:"roles"`
}

// CatalogMetadata is the versioned, threshold-signed built-in image catalog.
type CatalogMetadata struct {
	Type      string  `json:"_type"`
	Schema    int     `json:"schema"`
	Version   int     `json:"version"`
	Generated string  `json:"generated"`
	Expires   string  `json:"expires"`
	Images    []Image `json:"images"`
}

type VerifiedRoot struct {
	Metadata    RootMetadata
	GeneratedAt time.Time
	ExpiresAt   time.Time
	SHA256      string
	SignedBytes []byte
	Signatures  []MetadataSignature
	keys        map[string]ed25519.PublicKey
}

type VerifiedChannelCatalog struct {
	Metadata      CatalogMetadata
	GeneratedAt   time.Time
	ExpiresAt     time.Time
	SHA256        string
	SignedBytes   []byte
	SigningKeyIDs []string
}

func PublicKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}

func VerifyBootstrapRoot(data []byte, now time.Time) (*VerifiedRoot, error) {
	envelope, canonical, err := parseMetadataEnvelope(data, MaxRootMetadataBytes)
	if err != nil {
		return nil, err
	}
	var metadata RootMetadata
	if err := decodeStrictJSON(canonical, &metadata, "root metadata"); err != nil {
		return nil, err
	}
	verified, err := prepareRoot(metadata, canonical, envelope.Signatures, now)
	if err != nil {
		return nil, err
	}
	if _, err := verifyRoleSignatures(verified.Metadata.Roles.Root, verified.keys, canonical, envelope.Signatures); err != nil {
		return nil, fmt.Errorf("verify bootstrap root: %w", err)
	}
	return verified, nil
}

func VerifyRootUpdate(current *VerifiedRoot, data []byte, now time.Time) (*VerifiedRoot, error) {
	if current == nil {
		return nil, errors.New("current trusted root is required")
	}
	envelope, canonical, err := parseMetadataEnvelope(data, MaxRootMetadataBytes)
	if err != nil {
		return nil, err
	}
	var metadata RootMetadata
	if err := decodeStrictJSON(canonical, &metadata, "root metadata"); err != nil {
		return nil, err
	}
	candidate, err := prepareRoot(metadata, canonical, envelope.Signatures, now)
	if err != nil {
		return nil, err
	}
	if candidate.Metadata.Version == current.Metadata.Version {
		if candidate.SHA256 != current.SHA256 {
			return nil, fmt.Errorf("root version %d changed content", candidate.Metadata.Version)
		}
		return current, nil
	}
	if candidate.Metadata.Version != current.Metadata.Version+1 {
		return nil, fmt.Errorf("root version must advance exactly from %d to %d", current.Metadata.Version, current.Metadata.Version+1)
	}
	if candidate.GeneratedAt.Before(current.GeneratedAt) {
		return nil, errors.New("new root generation time precedes the trusted root")
	}
	if _, err := verifyRoleSignatures(current.Metadata.Roles.Root, current.keys, canonical, envelope.Signatures); err != nil {
		return nil, fmt.Errorf("verify new root with current root role: %w", err)
	}
	if _, err := verifyRoleSignatures(candidate.Metadata.Roles.Root, candidate.keys, canonical, envelope.Signatures); err != nil {
		return nil, fmt.Errorf("verify new root with replacement root role: %w", err)
	}
	return candidate, nil
}

func VerifyChannelCatalog(root *VerifiedRoot, data []byte, now time.Time) (*VerifiedChannelCatalog, error) {
	if root == nil {
		return nil, errors.New("trusted root is required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if !root.ExpiresAt.After(now) {
		return nil, fmt.Errorf("trusted root version %d has expired; install refreshed root metadata or a newer package", root.Metadata.Version)
	}
	envelope, canonical, err := parseMetadataEnvelope(data, MaxChannelCatalogBytes)
	if err != nil {
		return nil, err
	}
	var metadata CatalogMetadata
	if err := decodeStrictJSON(canonical, &metadata, "catalog metadata"); err != nil {
		return nil, err
	}
	generated, expires, err := validateMetadataTimes(metadata.Generated, metadata.Expires, now, maxCatalogMetadataLife, "catalog", true)
	if err != nil {
		return nil, err
	}
	if metadata.Type != "catalog" || metadata.Schema != TrustSchemaVersion || metadata.Version <= 0 {
		return nil, errors.New("catalog metadata type, schema, or version is invalid")
	}
	if len(metadata.Images) == 0 || len(metadata.Images) > MaxCatalogEntries {
		return nil, fmt.Errorf("catalog must contain between 1 and %d images", MaxCatalogEntries)
	}
	seen := make(map[string]struct{}, len(metadata.Images))
	previous := ""
	for i := range metadata.Images {
		if err := metadata.Images[i].validate(); err != nil {
			return nil, fmt.Errorf("catalog image %d: %w", i+1, err)
		}
		if _, exists := seen[metadata.Images[i].ID]; exists {
			return nil, fmt.Errorf("duplicate catalog image id %q", metadata.Images[i].ID)
		}
		if previous != "" && metadata.Images[i].ID <= previous {
			return nil, errors.New("catalog images must be sorted by id")
		}
		previous = metadata.Images[i].ID
		seen[metadata.Images[i].ID] = struct{}{}
	}
	keyIDs, err := verifyRoleSignatures(root.Metadata.Roles.Catalog, root.keys, canonical, envelope.Signatures)
	if err != nil {
		return nil, fmt.Errorf("verify catalog signatures: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return &VerifiedChannelCatalog{
		Metadata:      metadata,
		GeneratedAt:   generated,
		ExpiresAt:     expires,
		SHA256:        hex.EncodeToString(digest[:]),
		SignedBytes:   append([]byte(nil), canonical...),
		SigningKeyIDs: keyIDs,
	}, nil
}

func prepareRoot(metadata RootMetadata, canonical []byte, signatures []MetadataSignature, now time.Time) (*VerifiedRoot, error) {
	generated, expires, err := validateMetadataTimes(metadata.Generated, metadata.Expires, now, maxRootMetadataLifetime, "root", false)
	if err != nil {
		return nil, err
	}
	if metadata.Type != "root" || metadata.Schema != TrustSchemaVersion || metadata.Version <= 0 {
		return nil, errors.New("root metadata type, schema, or version is invalid")
	}
	if len(metadata.Keys) < 2 || len(metadata.Keys) > maximumTrustedKeyCount {
		return nil, fmt.Errorf("root metadata must contain between 2 and %d keys", maximumTrustedKeyCount)
	}
	keys := make(map[string]ed25519.PublicKey, len(metadata.Keys))
	previous := ""
	for i, key := range metadata.Keys {
		normalizedID := strings.ToLower(strings.TrimSpace(key.ID))
		if key.ID != normalizedID || key.ID == "" || key.Type != "ed25519" || strings.TrimSpace(key.Public) != key.Public {
			return nil, fmt.Errorf("root key %d is invalid", i+1)
		}
		publicBytes, err := decodeBase64Fixed(key.Public, ed25519.PublicKeySize, "Ed25519 public key")
		if err != nil {
			return nil, fmt.Errorf("decode root key %q: %w", key.ID, err)
		}
		publicKey := ed25519.PublicKey(publicBytes)
		if PublicKeyID(publicKey) != key.ID {
			return nil, fmt.Errorf("root key id %q does not match its public key", key.ID)
		}
		if _, exists := keys[key.ID]; exists {
			return nil, fmt.Errorf("duplicate root key %q", key.ID)
		}
		if previous != "" && key.ID <= previous {
			return nil, errors.New("root keys must be sorted by id")
		}
		previous = key.ID
		keys[key.ID] = publicKey
		metadata.Keys[i] = key
	}
	if err := validateRole("root", metadata.Roles.Root, keys, 2); err != nil {
		return nil, err
	}
	if err := validateRole("catalog", metadata.Roles.Catalog, keys, 1); err != nil {
		return nil, err
	}
	if err := validateMetadataSignatures(signatures); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return &VerifiedRoot{
		Metadata:    metadata,
		GeneratedAt: generated,
		ExpiresAt:   expires,
		SHA256:      hex.EncodeToString(digest[:]),
		SignedBytes: append([]byte(nil), canonical...),
		Signatures:  append([]MetadataSignature(nil), signatures...),
		keys:        keys,
	}, nil
}

func validateRole(name string, role TrustRole, keys map[string]ed25519.PublicKey, minimumThreshold int) error {
	if role.Threshold < minimumThreshold || role.Threshold > len(role.KeyIDs) {
		return fmt.Errorf("%s role threshold is invalid", name)
	}
	if len(role.KeyIDs) == 0 || len(role.KeyIDs) > maximumTrustedKeyCount {
		return fmt.Errorf("%s role key list is invalid", name)
	}
	previous := ""
	seen := make(map[string]struct{}, len(role.KeyIDs))
	for _, keyID := range role.KeyIDs {
		normalized := strings.ToLower(strings.TrimSpace(keyID))
		if keyID != normalized {
			return fmt.Errorf("%s role key ids must be lowercase hexadecimal values", name)
		}
		if _, ok := keys[keyID]; !ok {
			return fmt.Errorf("%s role references unknown key %q", name, keyID)
		}
		if _, ok := seen[keyID]; ok {
			return fmt.Errorf("%s role repeats key %q", name, keyID)
		}
		if previous != "" && keyID <= previous {
			return fmt.Errorf("%s role key ids must be sorted", name)
		}
		previous = keyID
		seen[keyID] = struct{}{}
	}
	return nil
}

func verifyRoleSignatures(role TrustRole, keys map[string]ed25519.PublicKey, signed []byte, signatures []MetadataSignature) ([]string, error) {
	if err := validateMetadataSignatures(signatures); err != nil {
		return nil, err
	}
	authorized := make(map[string]struct{}, len(role.KeyIDs))
	for _, keyID := range role.KeyIDs {
		authorized[keyID] = struct{}{}
	}
	valid := make([]string, 0, role.Threshold)
	for _, signature := range signatures {
		keyID := strings.ToLower(strings.TrimSpace(signature.KeyID))
		if _, ok := authorized[keyID]; !ok {
			continue
		}
		decoded, err := decodeBase64Fixed(signature.Sig, ed25519.SignatureSize, "metadata signature")
		if err != nil {
			return nil, fmt.Errorf("signature from %s: %w", keyID, err)
		}
		publicKey := keys[keyID]
		if !ed25519.Verify(publicKey, signed, decoded) {
			return nil, fmt.Errorf("signature from authorized key %s is invalid", keyID)
		}
		valid = append(valid, keyID)
	}
	if len(valid) < role.Threshold {
		return nil, fmt.Errorf("signature threshold not met: got %d valid signature(s), need %d", len(valid), role.Threshold)
	}
	sort.Strings(valid)
	return valid, nil
}

func validateMetadataSignatures(signatures []MetadataSignature) error {
	if len(signatures) == 0 || len(signatures) > maximumMetadataSignatures {
		return errors.New("metadata signature list is empty or too large")
	}
	seen := make(map[string]struct{}, len(signatures))
	previous := ""
	for _, signature := range signatures {
		keyID := strings.ToLower(strings.TrimSpace(signature.KeyID))
		if signature.KeyID != keyID || strings.TrimSpace(signature.Sig) != signature.Sig || len(keyID) != sha256.Size*2 {
			return errors.New("metadata signature key id or encoding is invalid")
		}
		if _, err := hex.DecodeString(keyID); err != nil {
			return errors.New("metadata signature key id is invalid")
		}
		if _, err := decodeBase64Fixed(signature.Sig, ed25519.SignatureSize, "metadata signature"); err != nil {
			return fmt.Errorf("signature from %s: %w", keyID, err)
		}
		if _, exists := seen[keyID]; exists {
			return fmt.Errorf("duplicate metadata signature from %s", keyID)
		}
		if previous != "" && keyID <= previous {
			return errors.New("metadata signatures must be sorted by key id")
		}
		previous = keyID
		seen[keyID] = struct{}{}
	}
	return nil
}

func parseMetadataEnvelope(data []byte, limit int) (MetadataEnvelope, []byte, error) {
	if len(data) == 0 || len(data) > limit {
		return MetadataEnvelope{}, nil, fmt.Errorf("metadata size must be between 1 and %d bytes", limit)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return MetadataEnvelope{}, nil, err
	}
	var envelope MetadataEnvelope
	if err := decodeStrictJSON(data, &envelope, "metadata envelope"); err != nil {
		return MetadataEnvelope{}, nil, err
	}
	if len(envelope.Signed) == 0 {
		return MetadataEnvelope{}, nil, errors.New("metadata envelope has no signed payload")
	}
	canonical, err := canonicalJSON(envelope.Signed)
	if err != nil {
		return MetadataEnvelope{}, nil, fmt.Errorf("canonicalize signed metadata: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(envelope.Signed), canonical) {
		return MetadataEnvelope{}, nil, errors.New("signed metadata is not canonical JSON")
	}
	if err := validateMetadataSignatures(envelope.Signatures); err != nil {
		return MetadataEnvelope{}, nil, err
	}
	return envelope, canonical, nil
}

func decodeStrictJSON(data []byte, output any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("parse %s: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%s contains trailing JSON data", label)
	}
	return nil
}

func validateMetadataTimes(generatedText, expiresText string, now time.Time, maximum time.Duration, label string, requireUnexpired bool) (time.Time, time.Time, error) {
	generated, err := time.Parse(time.RFC3339, generatedText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid %s generation time: %w", label, err)
	}
	expires, err := time.Parse(time.RFC3339, expiresText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid %s expiry time: %w", label, err)
	}
	generated, expires = generated.UTC(), expires.UTC()
	if !expires.After(generated) || expires.Sub(generated) > maximum {
		return time.Time{}, time.Time{}, fmt.Errorf("%s validity period is invalid", label)
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if generated.After(now.Add(24 * time.Hour)) {
		return time.Time{}, time.Time{}, fmt.Errorf("%s generation time is too far in the future", label)
	}
	if requireUnexpired && !expires.After(now) {
		return time.Time{}, time.Time{}, fmt.Errorf("%s metadata has expired", label)
	}
	return generated, expires, nil
}

func decodeBase64Fixed(value string, size int, label string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("%s must be standard base64 encoding of %d bytes", label, size)
	}
	return decoded, nil
}

func canonicalJSON(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	var output bytes.Buffer
	if err := writeCanonicalJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		encoded, _ := json.Marshal(typed)
		output.Write(encoded)
	case json.Number:
		text := typed.String()
		integer := new(big.Int)
		if _, ok := integer.SetString(text, 10); !ok || integer.String() != text {
			return fmt.Errorf("non-canonical or non-integer JSON number %q", text)
		}
		output.WriteString(text)
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			output.Write(encoded)
			output.WriteByte(':')
			if err := writeCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}
