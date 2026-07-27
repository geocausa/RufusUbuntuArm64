//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	catalogPublisherPolicySchema            = 1
	catalogPublisherPolicyPurpose           = "ffu-catalog-publisher-policy"
	catalogPublisherAuthorizationPlanSchema = 1
	catalogPublisherIdentityCertificate     = "certificate_sha256"
	catalogPublisherIdentitySPKI            = "subject_public_key_info_sha256"
	maxCatalogPublisherRules                = 256
	maxCatalogPublisherIdentifierBytes      = 128
)

// CatalogPublisherRule authorizes one exact publisher identity under one exact
// activated Authenticode root. IdentityKind selects either the complete signer
// certificate fingerprint or its SubjectPublicKeyInfo fingerprint.
type CatalogPublisherRule struct {
	ID                    string `json:"id"`
	IdentityKind          string `json:"identity_kind"`
	IdentitySHA256        string `json:"identity_sha256"`
	RootID                string `json:"root_id"`
	RootCertificateSHA256 string `json:"root_certificate_sha256"`
}

// CatalogPublisherPolicy is an explicit caller-provided allowlist. There is no
// production default policy and no implicit acceptance of every certificate
// chaining to an activated root.
type CatalogPublisherPolicy struct {
	Schema      int                    `json:"schema"`
	Purpose     string                 `json:"purpose"`
	PolicyID    string                 `json:"policy_id"`
	Version     uint64                 `json:"version"`
	GeneratedAt string                 `json:"generated_at"`
	ExpiresAt   string                 `json:"expires_at"`
	Rules       []CatalogPublisherRule `json:"rules"`
}

// CatalogPublisherAuthorizationPlan records the exact publisher-policy match.
// Revocation, timestamp, catalog hash-table authentication, target access and
// execution remain separate gates.
type CatalogPublisherAuthorizationPlan struct {
	Schema                        int      `json:"schema"`
	SourceFileSize                uint64   `json:"source_file_size"`
	CatalogSignaturePlanSHA256    string   `json:"catalog_signature_plan_sha256"`
	CatalogCertificatePlanSHA256  string   `json:"catalog_certificate_plan_sha256"`
	CatalogSHA256                 string   `json:"catalog_sha256"`
	PolicyID                      string   `json:"policy_id"`
	PolicyVersion                 uint64   `json:"policy_version"`
	PolicySHA256                  string   `json:"policy_sha256"`
	PolicyEvaluationTime          string   `json:"policy_evaluation_time"`
	MatchedRuleID                 string   `json:"matched_rule_id"`
	MatchedIdentityKind           string   `json:"matched_identity_kind"`
	MatchedIdentitySHA256         string   `json:"matched_identity_sha256"`
	SignerCertificateSHA256       string   `json:"signer_certificate_sha256"`
	SignerSubjectPublicKeySHA256  string   `json:"signer_subject_public_key_sha256"`
	SignerSubject                 string   `json:"signer_subject"`
	SignerIssuer                  string   `json:"signer_issuer"`
	SelectedRootID                string   `json:"selected_root_id"`
	SelectedRootSHA256            string   `json:"selected_root_sha256"`
	ExplicitPublisherPolicyUsed   bool     `json:"explicit_publisher_policy_used"`
	CertificateChainBuilt         bool     `json:"certificate_chain_built"`
	PublisherTrusted              bool     `json:"publisher_trusted"`
	HostTLSStoreConsulted         bool     `json:"host_tls_store_consulted"`
	RevocationChecked             bool     `json:"revocation_checked"`
	TimestampVerified             bool     `json:"timestamp_verified"`
	HashTableCatalogAuthenticated bool     `json:"hash_table_catalog_authenticated"`
	PlanSHA256                    string   `json:"plan_sha256"`
	Limitations                   []string `json:"limitations"`
}

// AuthorizeCatalogPublisher re-runs every preceding read-only catalog and chain
// gate, then requires exactly one match in an explicit versioned publisher
// policy. It performs no host-store lookup, network request, target access or
// execution.
func AuthorizeCatalogPublisher(ctx context.Context, reader interface {
	ReadAt([]byte, int64) (int, error)
}, size uint64, activation TrustBundleActivation, evaluationTime time.Time, sourcePolicy CatalogPublisherPolicy) (Inspection, HashTablePlan, CatalogMemberPlan, CatalogSignaturePlan, CatalogCertificateChainPlan, CatalogPublisherAuthorizationPlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, errors.New("FFU publisher-authorization context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, err
	}
	if evaluationTime.IsZero() {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, errors.New("FFU publisher-authorization evaluation time is zero")
	}
	evaluationTime = evaluationTime.UTC()
	policy, policySHA256, err := validateCatalogPublisherPolicy(sourcePolicy, evaluationTime)
	if err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, err
	}

	inspection, hashPlan, memberPlan, signaturePlan, chainPlan, err := BuildCatalogCertificateChain(ctx, reader, size, activation, evaluationTime)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}

	catalogBytes, err := readCatalogRegion(reader, inspection.CatalogOffset, uint64(inspection.Security.CatalogSize))
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}
	catalogDigest := sha256.Sum256(catalogBytes)
	if hex.EncodeToString(catalogDigest[:]) != chainPlan.CatalogSHA256 {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, errors.New("FFU catalog changed between certificate-chain and publisher authorization")
	}
	envelope, err := parseCatalogSignatureEnvelope(catalogBytes)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}
	signerIndex, signer, err := resolveCatalogSignerCertificate(envelope.certificates, envelope.signer)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}
	if signerIndex != signaturePlan.CertificateIndex || certificateFingerprint(signer) != chainPlan.SignerCertificateSHA256 {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, errors.New("FFU catalog signer changed between certificate-chain and publisher authorization")
	}
	signerSPKIDigest := sha256.Sum256(signer.RawSubjectPublicKeyInfo)
	signerSPKISHA256 := hex.EncodeToString(signerSPKIDigest[:])
	matched, err := matchCatalogPublisherRule(policy, chainPlan, signerSPKISHA256)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, CatalogPublisherAuthorizationPlan{}, err
	}

	signaturePlan.PublisherTrusted = true
	signaturePlan.HashTableCatalogAuthenticated = false
	signaturePlan.Limitations = []string{
		"the exact catalog member, SignerInfo signature, explicit-root certificate chain, and explicit publisher pin are verified",
		"revocation and trusted timestamp status remain unverified and no network request is performed",
		"the catalog hash table and final FFU integrity state remain unauthenticated",
		"no target is accepted and no regular-file, loop-device, physical-device, or image executor exists",
	}
	signaturePlan.PlanSHA256 = catalogSignaturePlanDigest(signaturePlan)

	chainPlan.CatalogSignaturePlanSHA256 = signaturePlan.PlanSHA256
	chainPlan.PublisherTrusted = true
	chainPlan.HashTableCatalogAuthenticated = false
	chainPlan.Limitations = []string{
		"only explicit activated FFU Authenticode roots and an explicit caller-supplied publisher policy are eligible",
		"the host TLS store is not consulted and no embedded self-signed root is trusted",
		"offline revocation status and trusted timestamp status remain unknown",
		"catalog hash-table authentication, target binding, writes and execution remain disabled",
	}
	chainPlan.PlanSHA256 = catalogCertificateChainPlanDigest(chainPlan)

	plan := CatalogPublisherAuthorizationPlan{
		Schema:                        catalogPublisherAuthorizationPlanSchema,
		SourceFileSize:                size,
		CatalogSignaturePlanSHA256:    signaturePlan.PlanSHA256,
		CatalogCertificatePlanSHA256:  chainPlan.PlanSHA256,
		CatalogSHA256:                 chainPlan.CatalogSHA256,
		PolicyID:                      policy.PolicyID,
		PolicyVersion:                 policy.Version,
		PolicySHA256:                  policySHA256,
		PolicyEvaluationTime:          evaluationTime.Format(time.RFC3339),
		MatchedRuleID:                 matched.ID,
		MatchedIdentityKind:           matched.IdentityKind,
		MatchedIdentitySHA256:         matched.IdentitySHA256,
		SignerCertificateSHA256:       chainPlan.SignerCertificateSHA256,
		SignerSubjectPublicKeySHA256:  signerSPKISHA256,
		SignerSubject:                 signer.Subject.String(),
		SignerIssuer:                  signer.Issuer.String(),
		SelectedRootID:                chainPlan.SelectedRootID,
		SelectedRootSHA256:            chainPlan.SelectedRootSHA256,
		ExplicitPublisherPolicyUsed:   true,
		CertificateChainBuilt:         true,
		PublisherTrusted:              true,
		HostTLSStoreConsulted:         false,
		RevocationChecked:             false,
		TimestampVerified:             false,
		HashTableCatalogAuthenticated: false,
		Limitations: []string{
			"publisher authorization is an exact certificate or SubjectPublicKeyInfo pin bound to one activated root",
			"the policy is explicitly supplied by the caller; this package contains no production publisher allowlist",
			"revocation and timestamp verification are separate future gates",
			"successful publisher authorization does not enable target access or execution",
		},
	}
	plan.PlanSHA256 = catalogPublisherAuthorizationPlanDigest(plan)
	return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, plan, nil
}

func validateCatalogPublisherPolicy(source CatalogPublisherPolicy, evaluationTime time.Time) (CatalogPublisherPolicy, string, error) {
	policy := snapshotCatalogPublisherPolicy(source)
	if policy.Schema != catalogPublisherPolicySchema || policy.Purpose != catalogPublisherPolicyPurpose {
		return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy has an invalid schema or purpose")
	}
	if err := validateCatalogPublisherIdentifier(policy.PolicyID, "policy_id"); err != nil {
		return CatalogPublisherPolicy{}, "", err
	}
	if policy.Version == 0 {
		return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy version is zero")
	}
	generatedAt, err := parseCanonicalCatalogPublisherTime(policy.GeneratedAt, "generated_at")
	if err != nil {
		return CatalogPublisherPolicy{}, "", err
	}
	expiresAt, err := parseCanonicalCatalogPublisherTime(policy.ExpiresAt, "expires_at")
	if err != nil {
		return CatalogPublisherPolicy{}, "", err
	}
	if !generatedAt.Before(expiresAt) {
		return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy expiry does not follow generation")
	}
	if evaluationTime.Before(generatedAt) || !evaluationTime.Before(expiresAt) {
		return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy is outside its validity interval")
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > maxCatalogPublisherRules {
		return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy rule count is outside bounds")
	}

	previousID := ""
	seenSelectors := make(map[string]struct{}, len(policy.Rules))
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if err := validateCatalogPublisherIdentifier(rule.ID, fmt.Sprintf("rules[%d].id", index)); err != nil {
			return CatalogPublisherPolicy{}, "", err
		}
		if index > 0 && rule.ID <= previousID {
			return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy rules are not strictly sorted by id")
		}
		previousID = rule.ID
		if rule.IdentityKind != catalogPublisherIdentityCertificate && rule.IdentityKind != catalogPublisherIdentitySPKI {
			return CatalogPublisherPolicy{}, "", fmt.Errorf("FFU publisher policy rule %q has unsupported identity kind %q", rule.ID, rule.IdentityKind)
		}
		identity, err := canonicalSHA256Fingerprint(rule.IdentitySHA256, fmt.Sprintf("rules[%d].identity_sha256", index))
		if err != nil {
			return CatalogPublisherPolicy{}, "", err
		}
		rule.IdentitySHA256 = identity
		if err := validateCatalogPublisherIdentifier(rule.RootID, fmt.Sprintf("rules[%d].root_id", index)); err != nil {
			return CatalogPublisherPolicy{}, "", err
		}
		rootFingerprint, err := canonicalSHA256Fingerprint(rule.RootCertificateSHA256, fmt.Sprintf("rules[%d].root_certificate_sha256", index))
		if err != nil {
			return CatalogPublisherPolicy{}, "", err
		}
		rule.RootCertificateSHA256 = rootFingerprint
		selector := strings.Join([]string{rule.IdentityKind, rule.IdentitySHA256, rule.RootID, rule.RootCertificateSHA256}, "\x00")
		if _, exists := seenSelectors[selector]; exists {
			return CatalogPublisherPolicy{}, "", errors.New("FFU publisher policy repeats an authorization selector")
		}
		seenSelectors[selector] = struct{}{}
	}
	return policy, catalogPublisherPolicyDigest(policy), nil
}

func matchCatalogPublisherRule(policy CatalogPublisherPolicy, chain CatalogCertificateChainPlan, signerSPKISHA256 string) (CatalogPublisherRule, error) {
	matches := make([]CatalogPublisherRule, 0, 1)
	for _, rule := range policy.Rules {
		if rule.RootID != chain.SelectedRootID || rule.RootCertificateSHA256 != chain.SelectedRootSHA256 {
			continue
		}
		matched := false
		switch rule.IdentityKind {
		case catalogPublisherIdentityCertificate:
			matched = rule.IdentitySHA256 == chain.SignerCertificateSHA256
		case catalogPublisherIdentitySPKI:
			matched = rule.IdentitySHA256 == signerSPKISHA256
		}
		if matched {
			matches = append(matches, rule)
		}
	}
	if len(matches) == 0 {
		return CatalogPublisherRule{}, errors.New("FFU catalog publisher is not authorized by the explicit publisher policy")
	}
	if len(matches) != 1 {
		return CatalogPublisherRule{}, fmt.Errorf("FFU catalog publisher authorization is ambiguous: %d policy rules match", len(matches))
	}
	return matches[0], nil
}

func snapshotCatalogPublisherPolicy(source CatalogPublisherPolicy) CatalogPublisherPolicy {
	clone := source
	clone.Rules = append([]CatalogPublisherRule(nil), source.Rules...)
	return clone
}

func parseCanonicalCatalogPublisherTime(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse FFU publisher policy %s: %w", field, err)
	}
	parsed = parsed.UTC()
	if parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("FFU publisher policy %s is not canonical UTC RFC3339", field)
	}
	return parsed, nil
}

func validateCatalogPublisherIdentifier(value, field string) error {
	if len(value) == 0 || len(value) > maxCatalogPublisherIdentifierBytes {
		return fmt.Errorf("FFU publisher policy %s length is outside bounds", field)
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if (current >= 'a' && current <= 'z') || (current >= '0' && current <= '9') || current == '.' || current == '_' || current == '-' {
			continue
		}
		return fmt.Errorf("FFU publisher policy %s contains a noncanonical character", field)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("FFU publisher policy %s contains an empty identifier component", field)
	}
	return nil
}

func catalogPublisherPolicyDigest(policy CatalogPublisherPolicy) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(policy.Schema))
	writeSignatureString(digest, policy.Purpose)
	writeSignatureString(digest, policy.PolicyID)
	writeSignatureUint64(digest, policy.Version)
	writeSignatureString(digest, policy.GeneratedAt)
	writeSignatureString(digest, policy.ExpiresAt)
	writeSignatureUint64(digest, uint64(len(policy.Rules)))
	for _, rule := range policy.Rules {
		writeCatalogPublisherRuleDigest(digest, rule)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeCatalogPublisherRuleDigest(digest hash.Hash, rule CatalogPublisherRule) {
	writeSignatureString(digest, rule.ID)
	writeSignatureString(digest, rule.IdentityKind)
	writeSignatureString(digest, rule.IdentitySHA256)
	writeSignatureString(digest, rule.RootID)
	writeSignatureString(digest, rule.RootCertificateSHA256)
}

func catalogPublisherAuthorizationPlanDigest(plan CatalogPublisherAuthorizationPlan) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(plan.Schema))
	writeSignatureUint64(digest, plan.SourceFileSize)
	writeSignatureString(digest, plan.CatalogSignaturePlanSHA256)
	writeSignatureString(digest, plan.CatalogCertificatePlanSHA256)
	writeSignatureString(digest, plan.CatalogSHA256)
	writeSignatureString(digest, plan.PolicyID)
	writeSignatureUint64(digest, plan.PolicyVersion)
	writeSignatureString(digest, plan.PolicySHA256)
	writeSignatureString(digest, plan.PolicyEvaluationTime)
	writeSignatureString(digest, plan.MatchedRuleID)
	writeSignatureString(digest, plan.MatchedIdentityKind)
	writeSignatureString(digest, plan.MatchedIdentitySHA256)
	writeSignatureString(digest, plan.SignerCertificateSHA256)
	writeSignatureString(digest, plan.SignerSubjectPublicKeySHA256)
	writeSignatureString(digest, plan.SignerSubject)
	writeSignatureString(digest, plan.SignerIssuer)
	writeSignatureString(digest, plan.SelectedRootID)
	writeSignatureString(digest, plan.SelectedRootSHA256)
	writeSignatureBool(digest, plan.ExplicitPublisherPolicyUsed)
	writeSignatureBool(digest, plan.CertificateChainBuilt)
	writeSignatureBool(digest, plan.PublisherTrusted)
	writeSignatureBool(digest, plan.HostTLSStoreConsulted)
	writeSignatureBool(digest, plan.RevocationChecked)
	writeSignatureBool(digest, plan.TimestampVerified)
	writeSignatureBool(digest, plan.HashTableCatalogAuthenticated)
	return hex.EncodeToString(digest.Sum(nil))
}
