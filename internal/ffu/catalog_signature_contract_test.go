package ffu

import (
	"bytes"
	"context"
	"testing"
)

func TestValidCatalogSignatureNeverClaimsCertificateOrPublisherTrust(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{})
	_, _, memberPlan, signaturePlan, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !memberPlan.HashTableMemberMatches || !signaturePlan.ContentDigestVerified || !signaturePlan.CryptographicSignatureVerified {
		t.Fatalf("cryptographic verification did not complete: member=%#v signature=%#v", memberPlan, signaturePlan)
	}
	if signaturePlan.CertificateChainBuilt || signaturePlan.PublisherTrusted || signaturePlan.HashTableCatalogAuthenticated {
		t.Fatalf("cryptographic validity silently became a trust claim: %#v", signaturePlan)
	}
}

func TestCatalogAuthenticationRequiresEveryIndependentTrustGate(t *testing.T) {
	plan := CatalogSignaturePlan{
		CryptographicSignatureVerified: true,
		CertificateChainBuilt:          true,
		PublisherTrusted:               false,
	}
	plan.HashTableCatalogAuthenticated = plan.CryptographicSignatureVerified && plan.CertificateChainBuilt && plan.PublisherTrusted
	if plan.HashTableCatalogAuthenticated {
		t.Fatalf("catalog authenticated without publisher trust: %#v", plan)
	}
	plan.PublisherTrusted = true
	plan.HashTableCatalogAuthenticated = plan.CryptographicSignatureVerified && plan.CertificateChainBuilt && plan.PublisherTrusted
	if !plan.HashTableCatalogAuthenticated {
		t.Fatalf("complete trust conjunction did not authenticate catalog: %#v", plan)
	}
}
