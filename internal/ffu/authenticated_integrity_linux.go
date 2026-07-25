//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	catalogHashAuthenticationPlanSchema = 1
	authenticatedIntegrityPlanSchema    = 1
)

// CatalogHashAuthenticationPlan binds the exact FFU hash table to a catalog
// member whose signature, explicit-root certificate chain, and publisher policy
// have all succeeded. Revocation, timestamp substitution, target access, and
// execution remain separate gates.
type CatalogHashAuthenticationPlan struct {
	Schema                         int      `json:"schema"`
	SourceFileSize                 uint64   `json:"source_file_size"`
	HashTablePlanSHA256            string   `json:"hash_table_plan_sha256"`
	CatalogMemberPlanSHA256        string   `json:"catalog_member_plan_sha256"`
	CatalogSignaturePlanSHA256     string   `json:"catalog_signature_plan_sha256"`
	CatalogCertificatePlanSHA256   string   `json:"catalog_certificate_plan_sha256"`
	CatalogPublisherPlanSHA256     string   `json:"catalog_publisher_plan_sha256"`
	CatalogSHA256                  string   `json:"catalog_sha256"`
	HashTableSHA256                string   `json:"hash_table_sha256"`
	HashEntryCount                 uint64   `json:"hash_entry_count"`
	HashTableMemberDigestOID       string   `json:"hash_table_member_digest_oid"`
	HashTableMemberMatches         bool     `json:"hash_table_member_matches"`
	CryptographicSignatureVerified bool     `json:"cryptographic_signature_verified"`
	CertificateChainBuilt          bool     `json:"certificate_chain_built"`
	PublisherTrusted               bool     `json:"publisher_trusted"`
	ExplicitPublisherPolicyUsed    bool     `json:"explicit_publisher_policy_used"`
	HostTLSStoreConsulted          bool     `json:"host_tls_store_consulted"`
	RevocationChecked              bool     `json:"revocation_checked"`
	TimestampVerified              bool     `json:"timestamp_verified"`
	HashTableCatalogAuthenticated  bool     `json:"hash_table_catalog_authenticated"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Limitations                    []string `json:"limitations"`
}

// AuthenticatedIntegrityPlan binds the single-store-v1 descriptor map to a
// publisher-authenticated FFU hash table and a complete read-only comparison of
// every covered source chunk. It still does not authorize target access or an
// executor.
type AuthenticatedIntegrityPlan struct {
	Schema                          int      `json:"schema"`
	SourceFileSize                  uint64   `json:"source_file_size"`
	DescriptorPlanSHA256            string   `json:"descriptor_plan_sha256"`
	HashTablePlanSHA256             string   `json:"hash_table_plan_sha256"`
	CatalogAuthenticationPlanSHA256 string   `json:"catalog_authentication_plan_sha256"`
	ContentVerificationSHA256       string   `json:"content_verification_sha256"`
	CatalogSHA256                   string   `json:"catalog_sha256"`
	HashTableSHA256                 string   `json:"hash_table_sha256"`
	HashEntryCount                  uint64   `json:"hash_entry_count"`
	CoverageOffset                  uint64   `json:"coverage_offset"`
	CoverageLength                  uint64   `json:"coverage_length"`
	CoverageEnd                     uint64   `json:"coverage_end"`
	ChunkSizeBytes                  uint64   `json:"chunk_size_bytes"`
	VerifiedChunkCount              uint64   `json:"verified_chunk_count"`
	FinalChunkZeroPaddingBytes      uint64   `json:"final_chunk_zero_padding_bytes"`
	HashTableCatalogAuthenticated   bool     `json:"hash_table_catalog_authenticated"`
	ContentMatchesHashTable         bool     `json:"content_matches_hash_table"`
	IntegrityAuthenticated          bool     `json:"integrity_authenticated"`
	RevocationChecked               bool     `json:"revocation_checked"`
	TimestampVerified               bool     `json:"timestamp_verified"`
	TargetSizeBindingRequired       bool     `json:"target_size_binding_required"`
	ExecutionSupported              bool     `json:"execution_supported"`
	PlanSHA256                      string   `json:"plan_sha256"`
	Limitations                     []string `json:"limitations"`
}

// AuthenticateCatalogHashTable re-runs the catalog member, signature, explicit
// certificate-chain, and publisher-policy gates. It then advances only the
// catalog-to-hash-table authentication state. No source content chunk, target,
// network location, host trust store, or executor is accepted here.
func AuthenticateCatalogHashTable(ctx context.Context, reader io.ReaderAt, size uint64, activation TrustBundleActivation, evaluationTime time.Time, sourcePolicy CatalogPublisherPolicy) (Inspection, HashTablePlan, CatalogMemberPlan, CatalogSignaturePlan, CatalogCertificateChainPlan, CatalogPublisherAuthorizationPlan, CatalogHashAuthenticationPlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, CatalogHashAuthenticationPlan{}, errors.New("FFU catalog-authentication context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, CatalogCertificateChainPlan{}, CatalogPublisherAuthorizationPlan{}, CatalogHashAuthenticationPlan{}, err
	}

	inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, err := AuthorizeCatalogPublisher(ctx, reader, size, activation, evaluationTime, sourcePolicy)
	if err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, err
	}
	if !memberPlan.HashTableMemberMatches || !signaturePlan.CryptographicSignatureVerified || !chainPlan.CertificateChainBuilt || !publisherPlan.PublisherTrusted || !publisherPlan.ExplicitPublisherPolicyUsed {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, errors.New("FFU catalog authentication prerequisites did not complete")
	}
	if hashPlan.SourceFileSize != size || memberPlan.SourceFileSize != size || signaturePlan.SourceFileSize != size || chainPlan.SourceFileSize != size || publisherPlan.SourceFileSize != size {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, errors.New("FFU catalog authentication plans disagree on source size")
	}
	if hashPlan.CatalogSHA256 != memberPlan.CatalogSHA256 || hashPlan.CatalogSHA256 != signaturePlan.CatalogSHA256 || hashPlan.CatalogSHA256 != chainPlan.CatalogSHA256 || hashPlan.CatalogSHA256 != publisherPlan.CatalogSHA256 {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, errors.New("FFU catalog authentication plans disagree on catalog digest")
	}
	if hashPlan.HashTableSHA256 != memberPlan.HashTableSHA256 || hashPlan.HashTableLength != memberPlan.HashTableLength {
		return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, CatalogHashAuthenticationPlan{}, errors.New("FFU catalog authentication plans disagree on hash-table identity")
	}

	memberPlan.CryptographicSignatureVerified = true
	memberPlan.CertificateChainBuilt = true
	memberPlan.PublisherTrusted = true
	memberPlan.HashTableCatalogAuthenticated = true
	memberPlan.Limitations = []string{
		"the exact HashTable.blob member, catalog signature, explicit-root certificate chain, and explicit publisher policy are verified",
		"the catalog member uses its legacy encoded SHA-1 digest only to bind the complete hash table",
		"revocation and trusted timestamp status remain unverified and no network request is performed",
		"source-content comparison, target binding, writes, and execution remain separate gates",
	}
	memberPlan.PlanSHA256 = catalogMemberPlanDigest(memberPlan)

	signaturePlan.CatalogMemberPlanSHA256 = memberPlan.PlanSHA256
	signaturePlan.CertificateChainBuilt = true
	signaturePlan.PublisherTrusted = true
	signaturePlan.HashTableCatalogAuthenticated = true
	signaturePlan.Limitations = []string{
		"the exact catalog member and SignerInfo signature authenticate the selected hash table under explicit chain and publisher policies",
		"revocation and trusted timestamp status remain unverified and no network request is performed",
		"source-content comparison, target binding, writes, and execution remain separate gates",
	}
	signaturePlan.PlanSHA256 = catalogSignaturePlanDigest(signaturePlan)

	chainPlan.CatalogMemberPlanSHA256 = memberPlan.PlanSHA256
	chainPlan.CatalogSignaturePlanSHA256 = signaturePlan.PlanSHA256
	chainPlan.PublisherTrusted = true
	chainPlan.HashTableCatalogAuthenticated = true
	chainPlan.Limitations = []string{
		"only explicit activated FFU Authenticode roots and an explicit publisher policy are eligible",
		"the selected catalog member now authenticates the exact embedded hash table",
		"offline revocation and trusted timestamp status remain unknown",
		"source-content comparison, target binding, writes, and execution remain disabled",
	}
	chainPlan.PlanSHA256 = catalogCertificateChainPlanDigest(chainPlan)

	publisherPlan.CatalogSignaturePlanSHA256 = signaturePlan.PlanSHA256
	publisherPlan.CatalogCertificatePlanSHA256 = chainPlan.PlanSHA256
	publisherPlan.HashTableCatalogAuthenticated = true
	publisherPlan.Limitations = []string{
		"the approved publisher's signed catalog authenticates the exact embedded hash table",
		"the policy is explicitly supplied by the caller; this package contains no production publisher allowlist",
		"revocation and timestamp verification remain separate policy gates",
		"successful catalog authentication does not enable target access or execution",
	}
	publisherPlan.PlanSHA256 = catalogPublisherAuthorizationPlanDigest(publisherPlan)

	hashPlan.CatalogAuthenticationAttempted = true
	hashPlan.HashTableCatalogAuthenticated = true
	hashPlan.Limitations = []string{
		"the exact hash table is authenticated by a verified catalog member, signature, explicit certificate chain, and publisher policy",
		"hash entries have not yet been compared with source chunks by this function",
		"revocation and trusted timestamp status remain unverified",
		"no target is accepted and no regular-file, loop-device, physical-device, or image executor exists",
	}
	hashPlan.PlanSHA256 = hashTablePlanDigest(hashPlan)

	plan := CatalogHashAuthenticationPlan{
		Schema:                         catalogHashAuthenticationPlanSchema,
		SourceFileSize:                 size,
		HashTablePlanSHA256:            hashPlan.PlanSHA256,
		CatalogMemberPlanSHA256:        memberPlan.PlanSHA256,
		CatalogSignaturePlanSHA256:     signaturePlan.PlanSHA256,
		CatalogCertificatePlanSHA256:   chainPlan.PlanSHA256,
		CatalogPublisherPlanSHA256:     publisherPlan.PlanSHA256,
		CatalogSHA256:                  hashPlan.CatalogSHA256,
		HashTableSHA256:                hashPlan.HashTableSHA256,
		HashEntryCount:                 hashPlan.HashEntryCount,
		HashTableMemberDigestOID:       memberPlan.HashTableMemberDigestOID,
		HashTableMemberMatches:         true,
		CryptographicSignatureVerified: true,
		CertificateChainBuilt:          true,
		PublisherTrusted:               true,
		ExplicitPublisherPolicyUsed:    true,
		HostTLSStoreConsulted:          false,
		RevocationChecked:              false,
		TimestampVerified:              false,
		HashTableCatalogAuthenticated:  true,
		Limitations: []string{
			"catalog authentication proves the approved publisher signed the catalog member that binds this exact hash table",
			"it does not by itself prove that source chunks match the table",
			"revocation and trusted timestamp status remain unverified",
			"no target access, write, flush, readback, or executor is authorized",
		},
	}
	plan.PlanSHA256 = catalogHashAuthenticationPlanDigest(plan)
	return inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, plan, nil
}

// AuthenticateSingleStoreV1Integrity combines catalog authentication with the
// complete source-content comparison and the existing single-store-v1 descriptor
// map. A successful result authenticates read-only source integrity but keeps
// execution disabled until target planning and provider qualification succeed.
func AuthenticateSingleStoreV1Integrity(ctx context.Context, reader io.ReaderAt, size uint64, activation TrustBundleActivation, evaluationTime time.Time, sourcePolicy CatalogPublisherPolicy) (Inspection, DescriptorPlan, HashTablePlan, ContentVerification, CatalogHashAuthenticationPlan, AuthenticatedIntegrityPlan, error) {
	if ctx == nil {
		return Inspection{}, DescriptorPlan{}, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, errors.New("FFU authenticated-integrity context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, DescriptorPlan{}, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, err
	}

	descriptorInspection, descriptorPlan, err := PlanSingleStoreV1(reader, size)
	if err != nil {
		return descriptorInspection, descriptorPlan, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, err
	}
	authInspection, authenticatedHashPlan, _, _, _, _, catalogPlan, err := AuthenticateCatalogHashTable(ctx, reader, size, activation, evaluationTime, sourcePolicy)
	if err != nil {
		return authInspection, descriptorPlan, authenticatedHashPlan, ContentVerification{}, catalogPlan, AuthenticatedIntegrityPlan{}, err
	}
	contentInspection, contentHashPlan, verification, err := VerifyHashTableContent(ctx, reader, size)
	if err != nil {
		return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, AuthenticatedIntegrityPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, AuthenticatedIntegrityPlan{}, err
	}
	if descriptorInspection.ImageHeaderOffset != authInspection.ImageHeaderOffset || descriptorInspection.ImageHeaderOffset != contentInspection.ImageHeaderOffset || descriptorPlan.SourceFileSize != size || descriptorPlan.ChunkSizeBytes != verification.ChunkSizeBytes {
		return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, AuthenticatedIntegrityPlan{}, errors.New("FFU descriptor, catalog, and content plans disagree on source geometry")
	}
	if err := requireMatchingFFUHashPlans(authenticatedHashPlan, contentHashPlan); err != nil {
		return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, AuthenticatedIntegrityPlan{}, err
	}
	if !catalogPlan.HashTableCatalogAuthenticated || !verification.ContentVerificationAttempted || !verification.ContentMatchesHashTable || verification.VerifiedChunkCount != verification.ExpectedChunkCount {
		return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, AuthenticatedIntegrityPlan{}, errors.New("FFU authenticated-integrity prerequisites did not complete")
	}

	authenticatedHashPlan.ContentVerificationAttempted = true
	authenticatedHashPlan.ContentMatchesHashTable = true
	authenticatedHashPlan.Limitations = []string{
		"the exact embedded hash table is authenticated by the approved catalog publisher",
		"every covered source chunk matches its corresponding SHA-256 entry",
		"revocation and trusted timestamp status remain unverified",
		"target binding, writes, flush, readback, and execution remain disabled",
	}
	authenticatedHashPlan.PlanSHA256 = hashTablePlanDigest(authenticatedHashPlan)

	verification.HashTableCatalogAuthenticated = true
	verification.IntegrityAuthenticated = true
	verification.Limitations = []string{
		"every covered source chunk matches a publisher-authenticated FFU hash table",
		"revocation and trusted timestamp status remain unverified",
		"the result authenticates this read-only source snapshot only",
		"no target access, write, flush, readback, or executor is authorized",
	}
	verification.VerificationSHA256 = contentVerificationDigest(verification)

	plan := AuthenticatedIntegrityPlan{
		Schema:                          authenticatedIntegrityPlanSchema,
		SourceFileSize:                  size,
		DescriptorPlanSHA256:            descriptorPlan.PlanSHA256,
		HashTablePlanSHA256:             authenticatedHashPlan.PlanSHA256,
		CatalogAuthenticationPlanSHA256: catalogPlan.PlanSHA256,
		ContentVerificationSHA256:       verification.VerificationSHA256,
		CatalogSHA256:                   catalogPlan.CatalogSHA256,
		HashTableSHA256:                 catalogPlan.HashTableSHA256,
		HashEntryCount:                  authenticatedHashPlan.HashEntryCount,
		CoverageOffset:                  verification.CoverageOffset,
		CoverageLength:                  verification.CoverageLength,
		CoverageEnd:                     verification.CoverageEnd,
		ChunkSizeBytes:                  verification.ChunkSizeBytes,
		VerifiedChunkCount:              verification.VerifiedChunkCount,
		FinalChunkZeroPaddingBytes:      verification.FinalChunkZeroPaddingBytes,
		HashTableCatalogAuthenticated:   true,
		ContentMatchesHashTable:         true,
		IntegrityAuthenticated:          true,
		RevocationChecked:               false,
		TimestampVerified:               false,
		TargetSizeBindingRequired:       descriptorPlan.TargetSizeBindingRequired,
		ExecutionSupported:              false,
		Limitations: []string{
			"the single-store-v1 descriptor map and every covered source chunk are bound to an approved publisher's signed catalog",
			"revocation and trusted timestamp status remain unverified",
			"target identity, capacity, end-relative resolution, validation checks, writes, flush, readback, and executor qualification remain required",
			"software authentication does not prove physical bootability or device health",
		},
	}
	plan.PlanSHA256 = authenticatedIntegrityPlanDigest(plan)
	return contentInspection, descriptorPlan, authenticatedHashPlan, verification, catalogPlan, plan, nil
}

func requireMatchingFFUHashPlans(authenticated, content HashTablePlan) error {
	if authenticated.SourceFileSize != content.SourceFileSize || authenticated.AlgorithmID != content.AlgorithmID || authenticated.DigestSizeBytes != content.DigestSizeBytes || authenticated.CatalogOffset != content.CatalogOffset || authenticated.CatalogLength != content.CatalogLength || authenticated.CatalogSHA256 != content.CatalogSHA256 || authenticated.HashTableOffset != content.HashTableOffset || authenticated.HashTableLength != content.HashTableLength || authenticated.HashTableSHA256 != content.HashTableSHA256 || authenticated.HashEntryCount != content.HashEntryCount {
		return fmt.Errorf("FFU catalog-authenticated and content-verification hash plans disagree")
	}
	return nil
}

func catalogHashAuthenticationPlanDigest(plan CatalogHashAuthenticationPlan) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(plan.Schema))
	writeSignatureUint64(digest, plan.SourceFileSize)
	writeSignatureString(digest, plan.HashTablePlanSHA256)
	writeSignatureString(digest, plan.CatalogMemberPlanSHA256)
	writeSignatureString(digest, plan.CatalogSignaturePlanSHA256)
	writeSignatureString(digest, plan.CatalogCertificatePlanSHA256)
	writeSignatureString(digest, plan.CatalogPublisherPlanSHA256)
	writeSignatureString(digest, plan.CatalogSHA256)
	writeSignatureString(digest, plan.HashTableSHA256)
	writeSignatureUint64(digest, plan.HashEntryCount)
	writeSignatureString(digest, plan.HashTableMemberDigestOID)
	writeSignatureBool(digest, plan.HashTableMemberMatches)
	writeSignatureBool(digest, plan.CryptographicSignatureVerified)
	writeSignatureBool(digest, plan.CertificateChainBuilt)
	writeSignatureBool(digest, plan.PublisherTrusted)
	writeSignatureBool(digest, plan.ExplicitPublisherPolicyUsed)
	writeSignatureBool(digest, plan.HostTLSStoreConsulted)
	writeSignatureBool(digest, plan.RevocationChecked)
	writeSignatureBool(digest, plan.TimestampVerified)
	writeSignatureBool(digest, plan.HashTableCatalogAuthenticated)
	return hex.EncodeToString(digest.Sum(nil))
}

func authenticatedIntegrityPlanDigest(plan AuthenticatedIntegrityPlan) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(plan.Schema))
	writeSignatureUint64(digest, plan.SourceFileSize)
	writeSignatureString(digest, plan.DescriptorPlanSHA256)
	writeSignatureString(digest, plan.HashTablePlanSHA256)
	writeSignatureString(digest, plan.CatalogAuthenticationPlanSHA256)
	writeSignatureString(digest, plan.ContentVerificationSHA256)
	writeSignatureString(digest, plan.CatalogSHA256)
	writeSignatureString(digest, plan.HashTableSHA256)
	writeSignatureUint64(digest, plan.HashEntryCount)
	writeSignatureUint64(digest, plan.CoverageOffset)
	writeSignatureUint64(digest, plan.CoverageLength)
	writeSignatureUint64(digest, plan.CoverageEnd)
	writeSignatureUint64(digest, plan.ChunkSizeBytes)
	writeSignatureUint64(digest, plan.VerifiedChunkCount)
	writeSignatureUint64(digest, plan.FinalChunkZeroPaddingBytes)
	writeSignatureBool(digest, plan.HashTableCatalogAuthenticated)
	writeSignatureBool(digest, plan.ContentMatchesHashTable)
	writeSignatureBool(digest, plan.IntegrityAuthenticated)
	writeSignatureBool(digest, plan.RevocationChecked)
	writeSignatureBool(digest, plan.TimestampVerified)
	writeSignatureBool(digest, plan.TargetSizeBindingRequired)
	writeSignatureBool(digest, plan.ExecutionSupported)
	return hex.EncodeToString(digest.Sum(nil))
}
