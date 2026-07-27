//go:build linux

package ffu

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
	"time"
)

const (
	catalogCertificateChainPlanSchema = 1
	maxCatalogCertificateChainDepth   = 16
)

// CatalogChainCertificate records one exact certificate in the selected
// leaf-to-root Authenticode path. EmbeddedIndex is -1 for an activated root
// that was not selected from the catalog certificate set.
type CatalogChainCertificate struct {
	Position              int    `json:"position"`
	Role                  string `json:"role"`
	EmbeddedIndex         int    `json:"embedded_index"`
	TrustAnchorID         string `json:"trust_anchor_id,omitempty"`
	CertificateSHA256     string `json:"certificate_sha256"`
	Subject               string `json:"subject"`
	Issuer                string `json:"issuer"`
	SerialNumber          string `json:"serial_number"`
	NotBefore             string `json:"not_before"`
	NotAfter              string `json:"not_after"`
	PublicKeyAlgorithm    string `json:"public_key_algorithm"`
	SignatureAlgorithm    string `json:"signature_algorithm"`
	IsCA                  bool   `json:"is_ca"`
	CanSignCertificates   bool   `json:"can_sign_certificates"`
	CanSignDigitalContent bool   `json:"can_sign_digital_content"`
}

// CatalogCertificateChainPlan records deterministic construction of exactly
// one certificate path from the already verified catalog signer to an explicit
// root returned by ActivateAuthenticatedTrustBundle. Publisher identity,
// revocation, timestamp, target, network, and execution policy remain separate.
type CatalogCertificateChainPlan struct {
	Schema                        int                       `json:"schema"`
	SourceFileSize                uint64                    `json:"source_file_size"`
	CatalogMemberPlanSHA256       string                    `json:"catalog_member_plan_sha256"`
	CatalogSignaturePlanSHA256    string                    `json:"catalog_signature_plan_sha256"`
	CatalogSHA256                 string                    `json:"catalog_sha256"`
	TrustActivationSHA256         string                    `json:"trust_activation_sha256"`
	TrustBundleGeneration         string                    `json:"trust_bundle_generation"`
	TrustBundleSequence           uint64                    `json:"trust_bundle_sequence"`
	PolicyEvaluationTime          string                    `json:"policy_evaluation_time"`
	EmbeddedCertificateCount      int                       `json:"embedded_certificate_count"`
	SignerCertificateSHA256       string                    `json:"signer_certificate_sha256"`
	SelectedRootID                string                    `json:"selected_root_id"`
	SelectedRootSHA256            string                    `json:"selected_root_sha256"`
	Chain                         []CatalogChainCertificate `json:"chain"`
	ExplicitTrustAnchorsUsed      bool                      `json:"explicit_trust_anchors_used"`
	DigitalSignatureUsageVerified bool                      `json:"digital_signature_usage_verified"`
	CodeSigningEKUVerified        bool                      `json:"code_signing_eku_verified"`
	CertificateValidityVerified   bool                      `json:"certificate_validity_verified"`
	DistrustPolicyChecked         bool                      `json:"distrust_policy_checked"`
	CertificateChainBuilt         bool                      `json:"certificate_chain_built"`
	HostTLSStoreConsulted         bool                      `json:"host_tls_store_consulted"`
	RevocationChecked             bool                      `json:"revocation_checked"`
	TimestampVerified             bool                      `json:"timestamp_verified"`
	PublisherTrusted              bool                      `json:"publisher_trusted"`
	HashTableCatalogAuthenticated bool                      `json:"hash_table_catalog_authenticated"`
	PlanSHA256                    string                    `json:"plan_sha256"`
	Limitations                   []string                  `json:"limitations"`
}

// BuildCatalogCertificateChain re-verifies the catalog member and SignerInfo,
// validates the exact activated trust capability, and constructs one unique
// leaf-to-root path under an explicit code-signing policy. It never consults
// the host TLS store and never performs network, publisher, target, or executor
// work.
func BuildCatalogCertificateChain(ctx context.Context, reader interface {
	ReadAt([]byte, int64) (int, error)
}, size uint64, activation TrustBundleActivation, evaluationTime time.Time) (Inspection, HashTablePlan, CatalogMemberPlan, CatalogSignaturePlan, CatalogCertificateChainPlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, errors.New("FFU catalog-chain context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, err
	}
	if evaluationTime.IsZero() {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, errors.New("FFU catalog-chain evaluation time is zero")
	}
	evaluationTime = evaluationTime.UTC()
	activation = snapshotTrustBundleActivation(activation)
	roots, rootIDs, distrust, err := validateCatalogChainActivation(activation)
	if err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, err
	}

	inspection, hashPlan, memberPlan, signaturePlan, err := VerifyCatalogSignature(ctx, reader, size)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	catalogBytes, err := readCatalogRegion(reader, inspection.CatalogOffset, uint64(inspection.Security.CatalogSize))
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	catalogDigest := sha256.Sum256(catalogBytes)
	if hex.EncodeToString(catalogDigest[:]) != signaturePlan.CatalogSHA256 {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, errors.New("FFU catalog changed between signature and chain planning")
	}
	envelope, err := parseCatalogSignatureEnvelope(catalogBytes)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	signerIndex, signer, err := resolveCatalogSignerCertificate(envelope.certificates, envelope.signer)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	if signerIndex != signaturePlan.CertificateIndex || certificateFingerprint(signer) != signaturePlan.CertificateSHA256 {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, errors.New("FFU catalog signer changed between signature and chain planning")
	}
	if err := rejectDuplicateCatalogCertificates(envelope.certificates); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	if err := validateCatalogSignerPolicy(signer, evaluationTime); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}

	selected, rootID, err := selectUniqueCatalogCertificateChain(signer, signerIndex, envelope.certificates, roots, rootIDs, distrust, evaluationTime)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, CatalogCertificateChainPlan{}, err
	}

	chainEntries := make([]CatalogChainCertificate, 0, len(selected))
	embeddedIndexes := make(map[string]int, len(envelope.certificates))
	for index, certificate := range envelope.certificates {
		embeddedIndexes[certificateFingerprint(certificate)] = index
	}
	for position, certificate := range selected {
		fingerprint := certificateFingerprint(certificate)
		role := "intermediate"
		anchorID := ""
		if position == 0 {
			role = "signer"
		}
		if position == len(selected)-1 {
			role = "root"
			anchorID = rootID
		}
		embeddedIndex := -1
		if current, ok := embeddedIndexes[fingerprint]; ok {
			embeddedIndex = current
		}
		chainEntries = append(chainEntries, CatalogChainCertificate{
			Position:              position,
			Role:                  role,
			EmbeddedIndex:         embeddedIndex,
			TrustAnchorID:         anchorID,
			CertificateSHA256:     fingerprint,
			Subject:               certificate.Subject.String(),
			Issuer:                certificate.Issuer.String(),
			SerialNumber:          certificate.SerialNumber.Text(16),
			NotBefore:             certificate.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:              certificate.NotAfter.UTC().Format(time.RFC3339),
			PublicKeyAlgorithm:    certificate.PublicKeyAlgorithm.String(),
			SignatureAlgorithm:    certificate.SignatureAlgorithm.String(),
			IsCA:                  certificate.IsCA,
			CanSignCertificates:   certificate.KeyUsage&x509.KeyUsageCertSign != 0,
			CanSignDigitalContent: certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		})
	}

	signaturePlan.CertificateChainBuilt = true
	signaturePlan.PublisherTrusted = false
	signaturePlan.HashTableCatalogAuthenticated = false
	signaturePlan.Limitations = []string{
		"the exact catalog member, SignerInfo signature, and one explicit-root code-signing certificate path are verified",
		"publisher identity is not yet approved, so the catalog and FFU remain unauthenticated",
		"revocation and trusted timestamp status are unverified and no network request is performed",
		"no target is accepted and no regular-file, loop-device, physical-device, or image executor exists",
	}
	signaturePlan.PlanSHA256 = catalogSignaturePlanDigest(signaturePlan)

	plan := CatalogCertificateChainPlan{
		Schema:                        catalogCertificateChainPlanSchema,
		SourceFileSize:                size,
		CatalogMemberPlanSHA256:       memberPlan.PlanSHA256,
		CatalogSignaturePlanSHA256:    signaturePlan.PlanSHA256,
		CatalogSHA256:                 signaturePlan.CatalogSHA256,
		TrustActivationSHA256:         activation.ActivationSHA256,
		TrustBundleGeneration:         activation.Generation,
		TrustBundleSequence:           activation.Sequence,
		PolicyEvaluationTime:          evaluationTime.Format(time.RFC3339),
		EmbeddedCertificateCount:      len(envelope.certificates),
		SignerCertificateSHA256:       signaturePlan.CertificateSHA256,
		SelectedRootID:                rootID,
		SelectedRootSHA256:            certificateFingerprint(selected[len(selected)-1]),
		Chain:                         chainEntries,
		ExplicitTrustAnchorsUsed:      true,
		DigitalSignatureUsageVerified: true,
		CodeSigningEKUVerified:        true,
		CertificateValidityVerified:   true,
		DistrustPolicyChecked:         true,
		CertificateChainBuilt:         true,
		HostTLSStoreConsulted:         false,
		RevocationChecked:             false,
		TimestampVerified:             false,
		PublisherTrusted:              false,
		HashTableCatalogAuthenticated: false,
		Limitations: []string{
			"only explicit activated FFU Authenticode roots are eligible; the host TLS store is not consulted",
			"the signer must be an end-entity certificate with digital-signature key usage and an explicit code-signing EKU",
			"certificate validity is evaluated at the caller-supplied policy time without timestamp substitution",
			"offline revocation status is unknown and publisher identity remains unapproved",
		},
	}
	plan.PlanSHA256 = catalogCertificateChainPlanDigest(plan)
	return inspection, hashPlan, memberPlan, signaturePlan, plan, nil
}

func validateCatalogChainActivation(activation TrustBundleActivation) ([]*x509.Certificate, map[string]string, map[string]struct{}, error) {
	if activation.capability == nil || activation.capability.activationSHA256 != activation.ActivationSHA256 {
		return nil, nil, nil, errors.New("FFU catalog-chain trust activation is not sealed by the verified activation boundary")
	}
	if activation.Schema != trustActivationSchema || activation.Purpose != trustActivationPurpose || activation.Generation == "" || activation.Sequence == 0 {
		return nil, nil, nil, errors.New("FFU catalog-chain trust activation has an invalid identity")
	}
	for _, pair := range []struct {
		value string
		field string
	}{
		{activation.BundleSHA256, "bundle_sha256"},
		{activation.PublicationPlanSHA256, "publication_plan_sha256"},
		{activation.PreActivationPlanSHA256, "pre_activation_plan_sha256"},
		{activation.ActivatedPlanSHA256, "activated_plan_sha256"},
		{activation.ActivationSHA256, "activation_sha256"},
	} {
		if _, err := canonicalSHA256Fingerprint(pair.value, "activation."+pair.field); err != nil {
			return nil, nil, nil, err
		}
	}
	activationTime, err := parseCanonicalTrustTime(activation.ActivationEvaluationTime, "activation_evaluation_time")
	if err != nil {
		return nil, nil, nil, err
	}
	if activation.RootCount != len(activation.Roots) || activation.RootCount == 0 || activation.RootCount > maxFFUTrustAnchors {
		return nil, nil, nil, errors.New("FFU catalog-chain trust activation has an invalid root count")
	}
	if activation.DistrustedCount != len(activation.DistrustedSHA256) || activation.DistrustedCount > maxFFUDistrustFingerprints {
		return nil, nil, nil, errors.New("FFU catalog-chain trust activation has an invalid distrust count")
	}
	if err := requireActivatedTrustPlan(activation.Plan); err != nil {
		return nil, nil, nil, err
	}
	if activation.Plan.Schema != ffuTrustBundleSchema || activation.Plan.Purpose != ffuTrustBundlePurpose || activation.Plan.Sequence != activation.Sequence || activation.Plan.BundleSHA256 != activation.BundleSHA256 {
		return nil, nil, nil, errors.New("FFU catalog-chain trust activation does not match its authenticated plan")
	}
	if activation.Plan.PlanSHA256 != activation.ActivatedPlanSHA256 || trustBundlePlanDigest(activation.Plan) != activation.Plan.PlanSHA256 {
		return nil, nil, nil, errors.New("FFU catalog-chain activated plan digest is invalid")
	}
	if activation.Plan.EvaluationTime != activationTime.Format(time.RFC3339) {
		return nil, nil, nil, errors.New("FFU catalog-chain activation evaluation time does not match the activated plan")
	}
	if !equalTrustBundleAuthentication(activation.Authentication, activation.Plan.Authentication) {
		return nil, nil, nil, errors.New("FFU catalog-chain activation authentication does not match the activated plan")
	}
	if trustBundleActivationDigest(activation) != activation.ActivationSHA256 {
		return nil, nil, nil, errors.New("FFU catalog-chain activation digest is invalid")
	}
	if activation.Plan.RootCount != len(activation.Plan.Roots) || activation.Plan.DistrustedCount != len(activation.Plan.DistrustedSHA256) || len(activation.Plan.Roots) != len(activation.Roots) || len(activation.Plan.DistrustedSHA256) != len(activation.DistrustedSHA256) {
		return nil, nil, nil, errors.New("FFU catalog-chain activation material counts do not match the activated plan")
	}

	roots := make([]*x509.Certificate, 0, len(activation.Roots))
	rootIDs := make(map[string]string, len(activation.Roots))
	seenIDs := make(map[string]struct{}, len(activation.Roots))
	previousRootID := ""
	for index, activated := range activation.Roots {
		if index > 0 && activated.Anchor.ID <= previousRootID {
			return nil, nil, nil, errors.New("FFU catalog-chain activated roots are not strictly sorted by id")
		}
		previousRootID = activated.Anchor.ID
		if len(activated.CertificateDER) == 0 || len(activated.CertificateDER) > maxFFUTrustCertificateDER {
			return nil, nil, nil, fmt.Errorf("FFU catalog-chain activated root %d DER size is invalid", index)
		}
		document := TrustAnchorDocument{
			ID:                   activated.Anchor.ID,
			CertificateDERBase64: base64.StdEncoding.EncodeToString(activated.CertificateDER),
			CertificateSHA256:    activated.Anchor.CertificateSHA256,
		}
		normalized, err := parseTrustAnchor(document, index)
		if err != nil {
			return nil, nil, nil, err
		}
		if normalized != activated.Anchor || normalized != activation.Plan.Roots[index] {
			return nil, nil, nil, fmt.Errorf("FFU catalog-chain activated root %q does not match authenticated metadata", activated.Anchor.ID)
		}
		if _, exists := seenIDs[activated.Anchor.ID]; exists {
			return nil, nil, nil, errors.New("FFU catalog-chain activation repeats a root id")
		}
		seenIDs[activated.Anchor.ID] = struct{}{}
		if _, exists := rootIDs[activated.Anchor.CertificateSHA256]; exists {
			return nil, nil, nil, errors.New("FFU catalog-chain activation repeats root certificate material")
		}
		certificate, err := x509.ParseCertificate(activated.CertificateDER)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse FFU catalog-chain activated root %q: %w", activated.Anchor.ID, err)
		}
		if err := validateCatalogCertificateAlgorithms(certificate); err != nil {
			return nil, nil, nil, fmt.Errorf("activated root %q: %w", activated.Anchor.ID, err)
		}
		roots = append(roots, certificate)
		rootIDs[activated.Anchor.CertificateSHA256] = activated.Anchor.ID
	}

	distrust := make(map[string]struct{}, len(activation.DistrustedSHA256))
	previous := ""
	for index, value := range activation.DistrustedSHA256 {
		fingerprint, err := canonicalSHA256Fingerprint(value, fmt.Sprintf("activation.distrusted_sha256[%d]", index))
		if err != nil {
			return nil, nil, nil, err
		}
		if index > 0 && fingerprint <= previous {
			return nil, nil, nil, errors.New("FFU catalog-chain activation distrust fingerprints are not strictly sorted")
		}
		if fingerprint != activation.Plan.DistrustedSHA256[index] {
			return nil, nil, nil, errors.New("FFU catalog-chain activation distrust policy does not match the activated plan")
		}
		if _, explicitRoot := rootIDs[fingerprint]; explicitRoot {
			return nil, nil, nil, errors.New("FFU catalog-chain activation distrust policy overlaps an activated root")
		}
		distrust[fingerprint] = struct{}{}
		previous = fingerprint
	}
	return roots, rootIDs, distrust, nil
}

func snapshotTrustBundleActivation(source TrustBundleActivation) TrustBundleActivation {
	clone := source
	clone.Roots = make([]ActivatedTrustAnchor, len(source.Roots))
	for index, root := range source.Roots {
		clone.Roots[index] = root
		clone.Roots[index].CertificateDER = append([]byte(nil), root.CertificateDER...)
	}
	clone.DistrustedSHA256 = append([]string(nil), source.DistrustedSHA256...)
	clone.Authentication = cloneTrustBundleAuthentication(source.Authentication)
	clone.Plan = source.Plan
	clone.Plan.Roots = append([]TrustAnchor(nil), source.Plan.Roots...)
	clone.Plan.DistrustedSHA256 = append([]string(nil), source.Plan.DistrustedSHA256...)
	clone.Plan.Authentication = cloneTrustBundleAuthentication(source.Plan.Authentication)
	clone.Plan.Limitations = append([]string(nil), source.Plan.Limitations...)
	return clone
}

func equalTrustBundleAuthentication(left, right *TrustBundleAuthentication) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if left.Schema != right.Schema || left.Purpose != right.Purpose || left.Sequence != right.Sequence || left.KeySetVersion != right.KeySetVersion || left.KeySetSHA256 != right.KeySetSHA256 || left.Threshold != right.Threshold || left.GeneratedAt != right.GeneratedAt || left.ExpiresAt != right.ExpiresAt || left.EvaluationTime != right.EvaluationTime || left.BundleSize != right.BundleSize || left.BundleSHA256 != right.BundleSHA256 || left.MetadataSHA256 != right.MetadataSHA256 || len(left.SigningKeyIDs) != len(right.SigningKeyIDs) {
		return false
	}
	for index := range left.SigningKeyIDs {
		if left.SigningKeyIDs[index] != right.SigningKeyIDs[index] {
			return false
		}
	}
	return true
}

func rejectDuplicateCatalogCertificates(certificates []*x509.Certificate) error {
	seen := make(map[string]struct{}, len(certificates))
	for index, certificate := range certificates {
		fingerprint := certificateFingerprint(certificate)
		if _, exists := seen[fingerprint]; exists {
			return fmt.Errorf("FFU catalog certificate set repeats certificate %d fingerprint %s", index, fingerprint)
		}
		seen[fingerprint] = struct{}{}
	}
	return nil
}

func validateCatalogSignerPolicy(certificate *x509.Certificate, evaluationTime time.Time) error {
	if certificate == nil {
		return errors.New("FFU catalog signer certificate is nil")
	}
	if certificate.IsCA {
		return errors.New("FFU catalog signer certificate must be an end-entity certificate")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("FFU catalog signer certificate lacks digital-signature key usage")
	}
	codeSigning := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			codeSigning = true
		}
	}
	if !codeSigning {
		return errors.New("FFU catalog signer certificate lacks an explicit code-signing extended key usage")
	}
	if evaluationTime.Before(certificate.NotBefore) || evaluationTime.After(certificate.NotAfter) {
		return errors.New("FFU catalog signer certificate is outside its validity interval")
	}
	if err := validateCatalogCertificateAlgorithms(certificate); err != nil {
		return fmt.Errorf("FFU catalog signer certificate: %w", err)
	}
	return nil
}

func selectUniqueCatalogCertificateChain(signer *x509.Certificate, signerIndex int, certificates, roots []*x509.Certificate, rootIDs map[string]string, distrust map[string]struct{}, evaluationTime time.Time) ([]*x509.Certificate, string, error) {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for index, certificate := range certificates {
		if index == signerIndex {
			continue
		}
		if _, explicitRoot := rootIDs[certificateFingerprint(certificate)]; explicitRoot {
			continue
		}
		intermediatePool.AddCert(certificate)
	}
	chains, err := signer.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   evaluationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return nil, "", fmt.Errorf("build FFU catalog certificate chain: %w", err)
	}

	type candidate struct {
		key    string
		chain  []*x509.Certificate
		rootID string
	}
	unique := make(map[string]candidate, len(chains))
	for _, chain := range chains {
		rootID, err := validateCatalogCertificatePath(chain, rootIDs, distrust, evaluationTime)
		if err != nil {
			continue
		}
		parts := make([]string, len(chain))
		for index, certificate := range chain {
			parts[index] = certificateFingerprint(certificate)
		}
		key := strings.Join(parts, "/")
		unique[key] = candidate{key: key, chain: chain, rootID: rootID}
	}
	if len(unique) == 0 {
		return nil, "", errors.New("FFU catalog has no certificate path satisfying the explicit Authenticode policy")
	}
	candidates := make([]candidate, 0, len(unique))
	for _, current := range unique {
		candidates = append(candidates, current)
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].key < candidates[right].key })
	if len(candidates) != 1 {
		return nil, "", fmt.Errorf("FFU catalog certificate path is ambiguous under the explicit policy: %d valid paths", len(candidates))
	}
	return candidates[0].chain, candidates[0].rootID, nil
}

func validateCatalogCertificatePath(chain []*x509.Certificate, rootIDs map[string]string, distrust map[string]struct{}, evaluationTime time.Time) (string, error) {
	if len(chain) < 2 || len(chain) > maxCatalogCertificateChainDepth {
		return "", errors.New("FFU catalog certificate path depth is outside policy bounds")
	}
	for index, certificate := range chain {
		fingerprint := certificateFingerprint(certificate)
		if _, blocked := distrust[fingerprint]; blocked {
			return "", fmt.Errorf("FFU catalog certificate path contains distrusted certificate %s", fingerprint)
		}
		if evaluationTime.Before(certificate.NotBefore) || evaluationTime.After(certificate.NotAfter) {
			return "", fmt.Errorf("FFU catalog certificate path certificate %d is outside its validity interval", index)
		}
		if err := validateCatalogCertificateAlgorithms(certificate); err != nil {
			return "", fmt.Errorf("FFU catalog certificate path certificate %d: %w", index, err)
		}
		if index > 0 {
			if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
				return "", fmt.Errorf("FFU catalog certificate path issuer %d is not an authorized certificate-signing CA", index)
			}
			if err := chain[index-1].CheckSignatureFrom(certificate); err != nil {
				return "", fmt.Errorf("verify FFU catalog certificate path edge %d: %w", index-1, err)
			}
		}
	}
	rootFingerprint := certificateFingerprint(chain[len(chain)-1])
	rootID, ok := rootIDs[rootFingerprint]
	if !ok {
		return "", errors.New("FFU catalog certificate path does not terminate at an activated root")
	}
	return rootID, nil
}

func validateCatalogCertificateAlgorithms(certificate *x509.Certificate) error {
	switch certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519:
	default:
		return fmt.Errorf("uses unsupported certificate signature algorithm %s", certificate.SignatureAlgorithm)
	}
	switch publicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if publicKey.N.BitLen() < 2048 {
			return fmt.Errorf("uses RSA public key smaller than 2048 bits")
		}
	case *ecdsa.PublicKey:
		if publicKey.Curve == nil || publicKey.Curve.Params() == nil || publicKey.Curve.Params().BitSize < 256 {
			return errors.New("uses elliptic-curve public key smaller than 256 bits")
		}
	case ed25519.PublicKey:
		if len(publicKey) != ed25519.PublicKeySize {
			return errors.New("uses malformed Ed25519 public key")
		}
	default:
		return fmt.Errorf("uses unsupported public key algorithm %s", certificate.PublicKeyAlgorithm)
	}
	return nil
}

func catalogCertificateChainPlanDigest(plan CatalogCertificateChainPlan) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(plan.Schema))
	writeSignatureUint64(digest, plan.SourceFileSize)
	writeSignatureString(digest, plan.CatalogMemberPlanSHA256)
	writeSignatureString(digest, plan.CatalogSignaturePlanSHA256)
	writeSignatureString(digest, plan.CatalogSHA256)
	writeSignatureString(digest, plan.TrustActivationSHA256)
	writeSignatureString(digest, plan.TrustBundleGeneration)
	writeSignatureUint64(digest, plan.TrustBundleSequence)
	writeSignatureString(digest, plan.PolicyEvaluationTime)
	writeSignatureUint64(digest, uint64(plan.EmbeddedCertificateCount))
	writeSignatureString(digest, plan.SignerCertificateSHA256)
	writeSignatureString(digest, plan.SelectedRootID)
	writeSignatureString(digest, plan.SelectedRootSHA256)
	writeSignatureUint64(digest, uint64(len(plan.Chain)))
	for _, certificate := range plan.Chain {
		writeChainCertificateDigest(digest, certificate)
	}
	writeSignatureBool(digest, plan.ExplicitTrustAnchorsUsed)
	writeSignatureBool(digest, plan.DigitalSignatureUsageVerified)
	writeSignatureBool(digest, plan.CodeSigningEKUVerified)
	writeSignatureBool(digest, plan.CertificateValidityVerified)
	writeSignatureBool(digest, plan.DistrustPolicyChecked)
	writeSignatureBool(digest, plan.CertificateChainBuilt)
	writeSignatureBool(digest, plan.HostTLSStoreConsulted)
	writeSignatureBool(digest, plan.RevocationChecked)
	writeSignatureBool(digest, plan.TimestampVerified)
	writeSignatureBool(digest, plan.PublisherTrusted)
	writeSignatureBool(digest, plan.HashTableCatalogAuthenticated)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeChainCertificateDigest(digest hash.Hash, certificate CatalogChainCertificate) {
	writeSignatureUint64(digest, uint64(certificate.Position))
	writeSignatureString(digest, certificate.Role)
	writeSignatureUint64(digest, uint64(certificate.EmbeddedIndex+1))
	writeSignatureString(digest, certificate.TrustAnchorID)
	writeSignatureString(digest, certificate.CertificateSHA256)
	writeSignatureString(digest, certificate.Subject)
	writeSignatureString(digest, certificate.Issuer)
	writeSignatureString(digest, certificate.SerialNumber)
	writeSignatureString(digest, certificate.NotBefore)
	writeSignatureString(digest, certificate.NotAfter)
	writeSignatureString(digest, certificate.PublicKeyAlgorithm)
	writeSignatureString(digest, certificate.SignatureAlgorithm)
	writeSignatureBool(digest, certificate.IsCA)
	writeSignatureBool(digest, certificate.CanSignCertificates)
	writeSignatureBool(digest, certificate.CanSignDigitalContent)
}
