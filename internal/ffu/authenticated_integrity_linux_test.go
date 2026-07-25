//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestAuthenticateCatalogHashTableAdvancesOnlyCatalogGate(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)

	inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, catalogPlan, err := AuthenticateCatalogHashTable(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || hashPlan.HashEntryCount != 6 {
		t.Fatalf("unexpected source geometry: inspection=%#v hash=%#v", inspection, hashPlan)
	}
	if !hashPlan.CatalogAuthenticationAttempted || !hashPlan.HashTableCatalogAuthenticated || hashPlan.ContentVerificationAttempted || hashPlan.ContentMatchesHashTable {
		t.Fatalf("hash-table gates crossed incorrectly: %#v", hashPlan)
	}
	if !memberPlan.HashTableMemberMatches || !memberPlan.CryptographicSignatureVerified || !memberPlan.CertificateChainBuilt || !memberPlan.PublisherTrusted || !memberPlan.HashTableCatalogAuthenticated {
		t.Fatalf("member authentication did not complete: %#v", memberPlan)
	}
	if !signaturePlan.CryptographicSignatureVerified || !signaturePlan.CertificateChainBuilt || !signaturePlan.PublisherTrusted || !signaturePlan.HashTableCatalogAuthenticated {
		t.Fatalf("signature authentication did not complete: %#v", signaturePlan)
	}
	if !chainPlan.CertificateChainBuilt || !chainPlan.PublisherTrusted || !chainPlan.HashTableCatalogAuthenticated || chainPlan.HostTLSStoreConsulted || chainPlan.RevocationChecked || chainPlan.TimestampVerified {
		t.Fatalf("chain authentication crossed an excluded boundary: %#v", chainPlan)
	}
	if !publisherPlan.ExplicitPublisherPolicyUsed || !publisherPlan.PublisherTrusted || !publisherPlan.HashTableCatalogAuthenticated || publisherPlan.RevocationChecked || publisherPlan.TimestampVerified {
		t.Fatalf("publisher authentication crossed an excluded boundary: %#v", publisherPlan)
	}
	if !catalogPlan.HashTableMemberMatches || !catalogPlan.CryptographicSignatureVerified || !catalogPlan.CertificateChainBuilt || !catalogPlan.PublisherTrusted || !catalogPlan.ExplicitPublisherPolicyUsed || !catalogPlan.HashTableCatalogAuthenticated {
		t.Fatalf("catalog authentication plan did not complete: %#v", catalogPlan)
	}
	if catalogPlan.HostTLSStoreConsulted || catalogPlan.RevocationChecked || catalogPlan.TimestampVerified {
		t.Fatalf("catalog authentication claimed excluded policy: %#v", catalogPlan)
	}
	if signaturePlan.CatalogMemberPlanSHA256 != memberPlan.PlanSHA256 || chainPlan.CatalogSignaturePlanSHA256 != signaturePlan.PlanSHA256 || publisherPlan.CatalogCertificatePlanSHA256 != chainPlan.PlanSHA256 {
		t.Fatalf("updated prerequisite plans are not digest-linked")
	}
	if catalogPlan.HashTablePlanSHA256 != hashPlan.PlanSHA256 || catalogPlan.CatalogMemberPlanSHA256 != memberPlan.PlanSHA256 || catalogPlan.CatalogSignaturePlanSHA256 != signaturePlan.PlanSHA256 || catalogPlan.CatalogCertificatePlanSHA256 != chainPlan.PlanSHA256 || catalogPlan.CatalogPublisherPlanSHA256 != publisherPlan.PlanSHA256 {
		t.Fatalf("catalog authentication evidence is not fully linked: %#v", catalogPlan)
	}
	if catalogPlan.PlanSHA256 != catalogHashAuthenticationPlanDigest(catalogPlan) || len(catalogPlan.PlanSHA256) != sha256.Size*2 {
		t.Fatalf("catalog authentication digest mismatch: %#v", catalogPlan)
	}
}

func TestAuthenticateSingleStoreV1IntegrityCompletesReadOnlyIntegrity(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentitySPKI)

	inspection, descriptor, hashPlan, verification, catalogPlan, plan, err := AuthenticateSingleStoreV1Integrity(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || descriptor.PayloadOffset != 12288 || descriptor.ChunkSizeBytes != 4096 {
		t.Fatalf("unexpected descriptor geometry: inspection=%#v descriptor=%#v", inspection, descriptor)
	}
	if !hashPlan.CatalogAuthenticationAttempted || !hashPlan.HashTableCatalogAuthenticated || !hashPlan.ContentVerificationAttempted || !hashPlan.ContentMatchesHashTable {
		t.Fatalf("combined hash-table state did not complete: %#v", hashPlan)
	}
	if !verification.ContentVerificationAttempted || !verification.ContentMatchesHashTable || !verification.HashTableCatalogAuthenticated || !verification.IntegrityAuthenticated || verification.VerifiedChunkCount != verification.ExpectedChunkCount {
		t.Fatalf("content integrity did not complete: %#v", verification)
	}
	if !catalogPlan.HashTableCatalogAuthenticated || !plan.HashTableCatalogAuthenticated || !plan.ContentMatchesHashTable || !plan.IntegrityAuthenticated {
		t.Fatalf("authenticated integrity plan did not complete: catalog=%#v integrity=%#v", catalogPlan, plan)
	}
	if plan.RevocationChecked || plan.TimestampVerified || plan.ExecutionSupported || !plan.TargetSizeBindingRequired {
		t.Fatalf("authenticated integrity crossed an excluded boundary: %#v", plan)
	}
	if plan.DescriptorPlanSHA256 != descriptor.PlanSHA256 || plan.HashTablePlanSHA256 != hashPlan.PlanSHA256 || plan.CatalogAuthenticationPlanSHA256 != catalogPlan.PlanSHA256 || plan.ContentVerificationSHA256 != verification.VerificationSHA256 {
		t.Fatalf("authenticated integrity evidence is not fully linked: %#v", plan)
	}
	if plan.PlanSHA256 != authenticatedIntegrityPlanDigest(plan) || len(plan.PlanSHA256) != sha256.Size*2 {
		t.Fatalf("authenticated integrity digest mismatch: %#v", plan)
	}

	_, _, secondHash, secondVerification, secondCatalog, secondPlan, err := AuthenticateSingleStoreV1Integrity(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondHash.PlanSHA256 != hashPlan.PlanSHA256 || secondVerification.VerificationSHA256 != verification.VerificationSHA256 || secondCatalog.PlanSHA256 != catalogPlan.PlanSHA256 || secondPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatal("authenticated integrity evidence changed across identical runs")
	}
}

func TestAuthenticateSingleStoreV1IntegrityRejectsChangedContent(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	data := append([]byte(nil), fixture.data...)
	data[12288] ^= 0xff

	_, _, _, verification, catalogPlan, plan, err := AuthenticateSingleStoreV1Integrity(
		context.Background(), bytes.NewReader(data), uint64(len(data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err == nil || !strings.Contains(err.Error(), "content chunk 2") {
		t.Fatalf("error=%v", err)
	}
	if !catalogPlan.HashTableCatalogAuthenticated {
		t.Fatalf("catalog should authenticate independently before content mismatch: %#v", catalogPlan)
	}
	if verification.ContentMatchesHashTable || verification.IntegrityAuthenticated || plan.IntegrityAuthenticated {
		t.Fatalf("changed content crossed integrity boundary: verification=%#v plan=%#v", verification, plan)
	}
}

func TestAuthenticateCatalogHashTableRejectsUnapprovedPublisher(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	policy.Rules[0].IdentitySHA256 = strings.Repeat("0", sha256.Size*2)

	_, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, catalogPlan, err := AuthenticateCatalogHashTable(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("error=%v", err)
	}
	if hashPlan.HashTableCatalogAuthenticated || memberPlan.HashTableCatalogAuthenticated || signaturePlan.HashTableCatalogAuthenticated || chainPlan.HashTableCatalogAuthenticated || publisherPlan.HashTableCatalogAuthenticated || catalogPlan.HashTableCatalogAuthenticated {
		t.Fatalf("unapproved publisher crossed catalog boundary")
	}
}

func TestAuthenticatedIntegrityRejectsNilAndCancelledContext(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	var nilContext context.Context
	if _, _, _, _, _, _, err := AuthenticateSingleStoreV1Integrity(nilContext, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, _, _, err := AuthenticateSingleStoreV1Integrity(ctx, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
}

func TestRequireMatchingFFUHashPlansRejectsChangedIdentity(t *testing.T) {
	left := HashTablePlan{SourceFileSize: 1, AlgorithmID: ffuAlgorithmSHA256, DigestSizeBytes: sha256.Size, CatalogSHA256: strings.Repeat("1", 64), HashTableSHA256: strings.Repeat("2", 64), HashEntryCount: 1}
	right := left
	right.HashTableSHA256 = strings.Repeat("3", 64)
	if err := requireMatchingFFUHashPlans(left, right); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("error=%v", err)
	}
}
