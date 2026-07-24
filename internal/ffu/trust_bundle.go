package ffu

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	ffuTrustBundleSchema       = 1
	ffuTrustBundlePurpose      = "ffu-authenticode"
	maxFFUTrustBundleBytes     = int64(4 << 20)
	maxFFUTrustAnchors         = 64
	maxFFUDistrustFingerprints = 4096
	maxFFUTrustCertificateDER  = 64 << 10
)

// TrustBundleDocument is the strict external JSON contract. Parsing and
// validating this document does not authenticate who published it.
type TrustBundleDocument struct {
	Schema           int                   `json:"schema"`
	Purpose          string                `json:"purpose"`
	Sequence         uint64                `json:"sequence"`
	GeneratedAt      string                `json:"generated_at"`
	ExpiresAt        string                `json:"expires_at"`
	Roots            []TrustAnchorDocument `json:"roots"`
	DistrustedSHA256 []string              `json:"distrusted_sha256"`
}

// TrustAnchorDocument carries one explicit DER root and its independently
// recorded SHA-256 fingerprint.
type TrustAnchorDocument struct {
	ID                   string `json:"id"`
	CertificateDERBase64 string `json:"certificate_der_base64"`
	CertificateSHA256    string `json:"certificate_sha256"`
}

// TrustAnchor records normalized, reviewable root metadata. It is not activated
// for chain construction until the containing bundle is authenticated by a
// separate policy gate.
type TrustAnchor struct {
	ID                 string `json:"id"`
	CertificateSHA256  string `json:"certificate_sha256"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	SerialNumber       string `json:"serial_number"`
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SelfSigned         bool   `json:"self_signed"`
	IsCA               bool   `json:"is_ca"`
	CanSignCertificates bool  `json:"can_sign_certificates"`
}

// TrustBundlePlan is a deterministic, read-only description of an explicit
// Authenticode trust bundle. It deliberately cannot make any certificate or
// publisher trusted in this tranche.
type TrustBundlePlan struct {
	Schema                     int           `json:"schema"`
	Purpose                    string        `json:"purpose"`
	Sequence                   uint64        `json:"sequence"`
	MinimumAcceptedSequence    uint64        `json:"minimum_accepted_sequence"`
	GeneratedAt                string        `json:"generated_at"`
	ExpiresAt                  string        `json:"expires_at"`
	EvaluationTime             string        `json:"evaluation_time"`
	RootCount                  int           `json:"root_count"`
	DistrustedCount            int           `json:"distrusted_count"`
	Roots                      []TrustAnchor `json:"roots"`
	DistrustedSHA256           []string      `json:"distrusted_sha256"`
	BundleSHA256               string        `json:"bundle_sha256"`
	PlanSHA256                 string        `json:"plan_sha256"`
	BundleStructureValidated   bool          `json:"bundle_structure_validated"`
	BundleSignatureAuthenticated bool        `json:"bundle_signature_authenticated"`
	TrustAnchorsActivated      bool          `json:"trust_anchors_activated"`
	HostTLSStoreConsulted      bool          `json:"host_tls_store_consulted"`
	CertificateChainBuilt      bool          `json:"certificate_chain_built"`
	PublisherTrusted           bool          `json:"publisher_trusted"`
	Limitations                []string      `json:"limitations"`
}

// ParseTrustBundle validates a bounded explicit trust-bundle document. The
// evaluation time and minimum sequence are supplied by the caller so rollback
// and expiry behavior remain deterministic and testable.
func ParseTrustBundle(reader io.Reader, minimumSequence uint64, evaluationTime time.Time) (TrustBundlePlan, error) {
	if reader == nil {
		return TrustBundlePlan{}, errors.New("FFU trust-bundle reader is nil")
	}
	if evaluationTime.IsZero() {
		return TrustBundlePlan{}, errors.New("FFU trust-bundle evaluation time is zero")
	}
	limited := io.LimitReader(reader, maxFFUTrustBundleBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return TrustBundlePlan{}, fmt.Errorf("read FFU trust bundle: %w", err)
	}
	if len(data) == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust bundle is empty")
	}
	if int64(len(data)) > maxFFUTrustBundleBytes {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle exceeds %d-byte limit", maxFFUTrustBundleBytes)
	}
	return ParseTrustBundleBytes(data, minimumSequence, evaluationTime)
}

// ParseTrustBundleBytes applies the same strict contract to an in-memory JSON
// document. No host trust store, network, target, or privileged path is used.
func ParseTrustBundleBytes(data []byte, minimumSequence uint64, evaluationTime time.Time) (TrustBundlePlan, error) {
	if len(data) == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust bundle is empty")
	}
	if int64(len(data)) > maxFFUTrustBundleBytes {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle exceeds %d-byte limit", maxFFUTrustBundleBytes)
	}
	if evaluationTime.IsZero() {
		return TrustBundlePlan{}, errors.New("FFU trust-bundle evaluation time is zero")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document TrustBundleDocument
	if err := decoder.Decode(&document); err != nil {
		return TrustBundlePlan{}, fmt.Errorf("decode FFU trust bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustBundlePlan{}, errors.New("FFU trust bundle contains multiple JSON values")
		}
		return TrustBundlePlan{}, fmt.Errorf("decode trailing FFU trust-bundle data: %w", err)
	}

	if document.Schema != ffuTrustBundleSchema {
		return TrustBundlePlan{}, fmt.Errorf("unsupported FFU trust-bundle schema %d", document.Schema)
	}
	if document.Purpose != ffuTrustBundlePurpose {
		return TrustBundlePlan{}, fmt.Errorf("unsupported FFU trust-bundle purpose %q", document.Purpose)
	}
	if document.Sequence == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust-bundle sequence must be non-zero")
	}
	if document.Sequence < minimumSequence {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust-bundle sequence %d is below rollback floor %d", document.Sequence, minimumSequence)
	}
	generatedAt, err := parseCanonicalTrustTime(document.GeneratedAt, "generated_at")
	if err != nil {
		return TrustBundlePlan{}, err
	}
	expiresAt, err := parseCanonicalTrustTime(document.ExpiresAt, "expires_at")
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if !expiresAt.After(generatedAt) {
		return TrustBundlePlan{}, errors.New("FFU trust-bundle expiry must be after generation time")
	}
	evaluationTime = evaluationTime.UTC()
	if evaluationTime.Before(generatedAt) {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle is not valid before %s", generatedAt.Format(time.RFC3339))
	}
	if !evaluationTime.Before(expiresAt) {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle expired at %s", expiresAt.Format(time.RFC3339))
	}
	if len(document.Roots) == 0 {
		return TrustBundlePlan{}, errors.New("FFU trust bundle contains no roots")
	}
	if len(document.Roots) > maxFFUTrustAnchors {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle contains %d roots, limit is %d", len(document.Roots), maxFFUTrustAnchors)
	}
	if len(document.DistrustedSHA256) > maxFFUDistrustFingerprints {
		return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle contains %d distrust fingerprints, limit is %d", len(document.DistrustedSHA256), maxFFUDistrustFingerprints)
	}

	roots := make([]TrustAnchor, 0, len(document.Roots))
	rootIDs := make(map[string]struct{}, len(document.Roots))
	rootFingerprints := make(map[string]struct{}, len(document.Roots))
	for index, rootDocument := range document.Roots {
		anchor, err := parseTrustAnchor(rootDocument, index)
		if err != nil {
			return TrustBundlePlan{}, err
		}
		if _, exists := rootIDs[anchor.ID]; exists {
			return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle has duplicate root id %q", anchor.ID)
		}
		rootIDs[anchor.ID] = struct{}{}
		if _, exists := rootFingerprints[anchor.CertificateSHA256]; exists {
			return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle has duplicate root certificate %s", anchor.CertificateSHA256)
		}
		rootFingerprints[anchor.CertificateSHA256] = struct{}{}
		roots = append(roots, anchor)
	}
	sort.Slice(roots, func(left, right int) bool {
		if roots[left].ID != roots[right].ID {
			return roots[left].ID < roots[right].ID
		}
		return roots[left].CertificateSHA256 < roots[right].CertificateSHA256
	})

	distrusted := make([]string, 0, len(document.DistrustedSHA256))
	distrustSet := make(map[string]struct{}, len(document.DistrustedSHA256))
	for index, value := range document.DistrustedSHA256 {
		fingerprint, err := canonicalSHA256Fingerprint(value, fmt.Sprintf("distrusted_sha256[%d]", index))
		if err != nil {
			return TrustBundlePlan{}, err
		}
		if _, exists := distrustSet[fingerprint]; exists {
			return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle has duplicate distrust fingerprint %s", fingerprint)
		}
		if _, exists := rootFingerprints[fingerprint]; exists {
			return TrustBundlePlan{}, fmt.Errorf("FFU trust bundle both trusts and distrusts certificate %s", fingerprint)
		}
		distrustSet[fingerprint] = struct{}{}
		distrusted = append(distrusted, fingerprint)
	}
	sort.Strings(distrusted)

	bundleDigest := sha256.Sum256(data)
	plan := TrustBundlePlan{
		Schema:                       ffuTrustBundleSchema,
		Purpose:                      ffuTrustBundlePurpose,
		Sequence:                     document.Sequence,
		MinimumAcceptedSequence:      minimumSequence,
		GeneratedAt:                  generatedAt.Format(time.RFC3339),
		ExpiresAt:                    expiresAt.Format(time.RFC3339),
		EvaluationTime:               evaluationTime.Format(time.RFC3339),
		RootCount:                    len(roots),
		DistrustedCount:              len(distrusted),
		Roots:                        roots,
		DistrustedSHA256:             distrusted,
		BundleSHA256:                 hex.EncodeToString(bundleDigest[:]),
		BundleStructureValidated:     true,
		BundleSignatureAuthenticated: false,
		TrustAnchorsActivated:        false,
		HostTLSStoreConsulted:        false,
		CertificateChainBuilt:        false,
		PublisherTrusted:             false,
		Limitations: []string{
			"the bundle structure and root certificates are validated but the bundle publisher is not authenticated",
			"roots remain inactive until a separate signed trust-metadata policy succeeds",
			"the host TLS certificate store is never treated as an Authenticode policy source",
			"no certificate chain, publisher decision, target binding, network request, or executor is performed",
		},
	}
	plan.PlanSHA256 = trustBundlePlanDigest(plan)
	return plan, nil
}

func parseTrustAnchor(document TrustAnchorDocument, index int) (TrustAnchor, error) {
	if !validTrustAnchorID(document.ID) {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %d has invalid id %q", index, document.ID)
	}
	fingerprint, err := canonicalSHA256Fingerprint(document.CertificateSHA256, fmt.Sprintf("roots[%d].certificate_sha256", index))
	if err != nil {
		return TrustAnchor{}, err
	}
	decoder := base64.StdEncoding.Strict()
	der, err := decoder.DecodeString(document.CertificateDERBase64)
	if err != nil {
		return TrustAnchor{}, fmt.Errorf("decode FFU trust-bundle root %q DER: %w", document.ID, err)
	}
	if len(der) == 0 || len(der) > maxFFUTrustCertificateDER {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q DER length %d is outside 1..%d", document.ID, len(der), maxFFUTrustCertificateDER)
	}
	calculated := sha256.Sum256(der)
	calculatedText := hex.EncodeToString(calculated[:])
	providedBytes, _ := hex.DecodeString(fingerprint)
	if subtle.ConstantTimeCompare(calculated[:], providedBytes) != 1 {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q fingerprint does not match DER", document.ID)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return TrustAnchor{}, fmt.Errorf("parse FFU trust-bundle root %q certificate: %w", document.ID, err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q is not a valid CA certificate", document.ID)
	}
	canSign := certificate.KeyUsage&x509.KeyUsageCertSign != 0
	if !canSign {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q lacks certificate-signing key usage", document.ID)
	}
	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q is not self-issued", document.ID)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return TrustAnchor{}, fmt.Errorf("verify FFU trust-bundle root %q self-signature: %w", document.ID, err)
	}
	if !certificate.NotAfter.After(certificate.NotBefore) {
		return TrustAnchor{}, fmt.Errorf("FFU trust-bundle root %q has an invalid validity interval", document.ID)
	}
	return TrustAnchor{
		ID:                  document.ID,
		CertificateSHA256:   calculatedText,
		Subject:             certificate.Subject.String(),
		Issuer:              certificate.Issuer.String(),
		SerialNumber:        certificate.SerialNumber.Text(16),
		NotBefore:           certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:            certificate.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm:  certificate.PublicKeyAlgorithm.String(),
		SignatureAlgorithm:  certificate.SignatureAlgorithm.String(),
		SelfSigned:          true,
		IsCA:                true,
		CanSignCertificates: canSign,
	}, nil
}

func parseCanonicalTrustTime(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse FFU trust-bundle %s: %w", field, err)
	}
	parsed = parsed.UTC()
	if value != parsed.Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("FFU trust-bundle %s must use canonical UTC RFC3339", field)
	}
	return parsed, nil
}

func canonicalSHA256Fingerprint(value, field string) (string, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return "", fmt.Errorf("FFU trust-bundle %s must be 64 lowercase hexadecimal characters", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("FFU trust-bundle %s is not a SHA-256 fingerprint", field)
	}
	return value, nil
}

func validTrustAnchorID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, current := range value {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || current == '.' || current == '_' || current == '-' {
			continue
		}
		return false
	}
	return true
}

func trustBundlePlanDigest(plan TrustBundlePlan) string {
	digest := sha256.New()
	writeTrustUint64(digest, uint64(plan.Schema))
	writeTrustString(digest, plan.Purpose)
	writeTrustUint64(digest, plan.Sequence)
	writeTrustUint64(digest, plan.MinimumAcceptedSequence)
	writeTrustString(digest, plan.GeneratedAt)
	writeTrustString(digest, plan.ExpiresAt)
	writeTrustString(digest, plan.EvaluationTime)
	writeTrustString(digest, plan.BundleSHA256)
	writeTrustUint64(digest, uint64(len(plan.Roots)))
	for _, root := range plan.Roots {
		writeTrustString(digest, root.ID)
		writeTrustString(digest, root.CertificateSHA256)
		writeTrustString(digest, root.Subject)
		writeTrustString(digest, root.Issuer)
		writeTrustString(digest, root.SerialNumber)
		writeTrustString(digest, root.NotBefore)
		writeTrustString(digest, root.NotAfter)
		writeTrustString(digest, root.PublicKeyAlgorithm)
		writeTrustString(digest, root.SignatureAlgorithm)
		writeTrustBool(digest, root.SelfSigned)
		writeTrustBool(digest, root.IsCA)
		writeTrustBool(digest, root.CanSignCertificates)
	}
	writeTrustUint64(digest, uint64(len(plan.DistrustedSHA256)))
	for _, fingerprint := range plan.DistrustedSHA256 {
		writeTrustString(digest, fingerprint)
	}
	writeTrustBool(digest, plan.BundleStructureValidated)
	writeTrustBool(digest, plan.BundleSignatureAuthenticated)
	writeTrustBool(digest, plan.TrustAnchorsActivated)
	writeTrustBool(digest, plan.HostTLSStoreConsulted)
	writeTrustBool(digest, plan.CertificateChainBuilt)
	writeTrustBool(digest, plan.PublisherTrusted)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeTrustUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeTrustString(digest hash.Hash, value string) {
	writeTrustUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeTrustBool(digest hash.Hash, value bool) {
	if value {
		writeTrustUint64(digest, 1)
		return
	}
	writeTrustUint64(digest, 0)
}
