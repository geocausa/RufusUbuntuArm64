package ffu

import (
	"bytes"
	"context"
	"testing"
)

func TestCatalogMemberMatchNeverClaimsPublisherTrust(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{})
	_, _, plan, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HashTableMemberMatches || !plan.SignatureStructureParsed {
		t.Fatalf("member binding did not complete: %#v", plan)
	}
	if plan.CryptographicSignatureVerified || plan.CertificateChainBuilt || plan.PublisherTrusted || plan.HashTableCatalogAuthenticated {
		t.Fatalf("member matching silently became a trust claim: %#v", plan)
	}
}

func TestCatalogStructureWithoutCertificateRemainsUntrustedMetadata(t *testing.T) {
	parsed, err := parseWindowsCatalog(catalogMemberFixtureForFuzz())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.memberName != catalogHashTableMember || len(parsed.memberDigest) == 0 || len(parsed.signers) != 1 {
		t.Fatalf("unexpected certificate-free catalog metadata: %#v", parsed)
	}
	if len(parsed.certificates) != 0 {
		t.Fatalf("certificate-free fixture produced certificates: %#v", parsed.certificates)
	}
}
