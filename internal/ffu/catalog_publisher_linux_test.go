//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeCatalogPublisherWithExactCertificatePin(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	inspection, hashPlan, memberPlan, signaturePlan, chainPlan, publisherPlan, err := AuthorizeCatalogPublisher(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || hashPlan.HashEntryCount != 6 || !memberPlan.HashTableMemberMatches {
		t.Fatalf("unexpected prerequisite state: inspection=%#v hash=%#v member=%#v", inspection, hashPlan, memberPlan)
	}
	if !signaturePlan.CryptographicSignatureVerified || !signaturePlan.CertificateChainBuilt || !signaturePlan.PublisherTrusted || signaturePlan.HashTableCatalogAuthenticated {
		t.Fatalf("signature publisher gates crossed incorrectly: %#v", signaturePlan)
	}
	if !chainPlan.CertificateChainBuilt || !chainPlan.PublisherTrusted || chainPlan.HashTableCatalogAuthenticated || chainPlan.RevocationChecked || chainPlan.TimestampVerified {
		t.Fatalf("chain publisher gates crossed incorrectly: %#v", chainPlan)
	}
	if !publisherPlan.ExplicitPublisherPolicyUsed || !publisherPlan.CertificateChainBuilt || !publisherPlan.PublisherTrusted {
		t.Fatalf("publisher policy did not complete: %#v", publisherPlan)
	}
	if publisherPlan.HostTLSStoreConsulted || publisherPlan.RevocationChecked || publisherPlan.TimestampVerified || publisherPlan.HashTableCatalogAuthenticated {
		t.Fatalf("publisher policy crossed a later boundary: %#v", publisherPlan)
	}
	if publisherPlan.PolicyID != policy.PolicyID || publisherPlan.PolicyVersion != policy.Version || publisherPlan.MatchedRuleID != "allow-test-publisher" {
		t.Fatalf("unexpected policy match: %#v", publisherPlan)
	}
	if publisherPlan.MatchedIdentityKind != catalogPublisherIdentityCertificate || publisherPlan.MatchedIdentitySHA256 != certificateFingerprint(fixture.leaf) {
		t.Fatalf("unexpected certificate identity match: %#v", publisherPlan)
	}
	if publisherPlan.SelectedRootID != "test.authenticode.root" || publisherPlan.SelectedRootSHA256 != certificateFingerprint(fixture.root) {
		t.Fatalf("unexpected root binding: %#v", publisherPlan)
	}
	if publisherPlan.CatalogSignaturePlanSHA256 != signaturePlan.PlanSHA256 || publisherPlan.CatalogCertificatePlanSHA256 != chainPlan.PlanSHA256 {
		t.Fatalf("publisher plan did not bind preceding plans: %#v", publisherPlan)
	}
	if publisherPlan.PolicySHA256 != catalogPublisherPolicyDigest(policy) || publisherPlan.PlanSHA256 != catalogPublisherAuthorizationPlanDigest(publisherPlan) {
		t.Fatalf("publisher plan digest mismatch: %#v", publisherPlan)
	}
	if len(publisherPlan.PlanSHA256) != sha256.Size*2 || len(publisherPlan.SignerSubjectPublicKeySHA256) != sha256.Size*2 {
		t.Fatalf("unexpected publisher digest sizes: %#v", publisherPlan)
	}

	_, _, _, secondSignature, secondChain, secondPublisher, err := AuthorizeCatalogPublisher(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondSignature.PlanSHA256 != signaturePlan.PlanSHA256 || secondChain.PlanSHA256 != chainPlan.PlanSHA256 || secondPublisher.PlanSHA256 != publisherPlan.PlanSHA256 {
		t.Fatalf("publisher authorization changed across identical runs")
	}
}

func TestAuthorizeCatalogPublisherWithSubjectPublicKeyPin(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentitySPKI)
	_, _, _, signaturePlan, chainPlan, publisherPlan, err := AuthorizeCatalogPublisher(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture.leaf.RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(digest[:])
	if publisherPlan.MatchedIdentityKind != catalogPublisherIdentitySPKI || publisherPlan.MatchedIdentitySHA256 != want || publisherPlan.SignerSubjectPublicKeySHA256 != want {
		t.Fatalf("unexpected SPKI authorization: %#v", publisherPlan)
	}
	if !signaturePlan.PublisherTrusted || !chainPlan.PublisherTrusted || !publisherPlan.PublisherTrusted {
		t.Fatalf("SPKI authorization did not cross publisher gate")
	}
}

func TestAuthorizeCatalogPublisherRejectsInvalidOrUnmatchedPolicy(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	base := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	tests := []struct {
		name   string
		mutate func(*CatalogPublisherPolicy)
		want   string
	}{
		{name: "schema", mutate: func(policy *CatalogPublisherPolicy) { policy.Schema++ }, want: "invalid schema or purpose"},
		{name: "purpose", mutate: func(policy *CatalogPublisherPolicy) { policy.Purpose = "other" }, want: "invalid schema or purpose"},
		{name: "policy id", mutate: func(policy *CatalogPublisherPolicy) { policy.PolicyID = "Publisher" }, want: "noncanonical character"},
		{name: "version", mutate: func(policy *CatalogPublisherPolicy) { policy.Version = 0 }, want: "version is zero"},
		{name: "noncanonical generation", mutate: func(policy *CatalogPublisherPolicy) { policy.GeneratedAt = "2026-07-25T11:00:00+00:00" }, want: "not canonical UTC"},
		{name: "expired", mutate: func(policy *CatalogPublisherPolicy) {
			policy.ExpiresAt = catalogChainEvaluationTime.Format(time.RFC3339)
		}, want: "outside its validity"},
		{name: "not yet valid", mutate: func(policy *CatalogPublisherPolicy) {
			policy.GeneratedAt = catalogChainEvaluationTime.Add(time.Minute).Format(time.RFC3339)
		}, want: "outside its validity"},
		{name: "no rules", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules = nil }, want: "rule count"},
		{name: "unsupported identity", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules[0].IdentityKind = "subject" }, want: "unsupported identity"},
		{name: "noncanonical identity", mutate: func(policy *CatalogPublisherPolicy) {
			policy.Rules[0].IdentitySHA256 = strings.ToUpper(policy.Rules[0].IdentitySHA256)
		}, want: "64 lowercase hexadecimal"},
		{name: "invalid root id", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules[0].RootID = "Test.Root" }, want: "noncanonical character"},
		{name: "unsorted", mutate: func(policy *CatalogPublisherPolicy) {
			second := policy.Rules[0]
			second.ID = "a-rule"
			policy.Rules = append(policy.Rules, second)
		}, want: "not strictly sorted"},
		{name: "duplicate selector", mutate: func(policy *CatalogPublisherPolicy) {
			second := policy.Rules[0]
			policy.Rules[0].ID = "a-rule"
			second.ID = "b-rule"
			policy.Rules = append(policy.Rules, second)
		}, want: "repeats an authorization selector"},
		{name: "wrong signer", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules[0].IdentitySHA256 = strings.Repeat("0", 64) }, want: "not authorized"},
		{name: "wrong root id", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules[0].RootID = "other.root" }, want: "not authorized"},
		{name: "wrong root fingerprint", mutate: func(policy *CatalogPublisherPolicy) { policy.Rules[0].RootCertificateSHA256 = strings.Repeat("1", 64) }, want: "not authorized"},
		{name: "ambiguous certificate and spki", mutate: func(policy *CatalogPublisherPolicy) {
			spki := policy.Rules[0]
			policy.Rules[0].ID = "allow-cert"
			spki.ID = "allow-spki"
			spki.IdentityKind = catalogPublisherIdentitySPKI
			digest := sha256.Sum256(fixture.leaf.RawSubjectPublicKeyInfo)
			spki.IdentitySHA256 = hex.EncodeToString(digest[:])
			policy.Rules = append(policy.Rules, spki)
		}, want: "ambiguous"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := cloneCatalogPublisherPolicyForTest(base)
			test.mutate(&policy)
			_, _, _, signaturePlan, chainPlan, publisherPlan, err := AuthorizeCatalogPublisher(
				context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
			if signaturePlan.PublisherTrusted || chainPlan.PublisherTrusted || publisherPlan.PublisherTrusted || publisherPlan.HashTableCatalogAuthenticated {
				t.Fatalf("rejected publisher policy crossed a trust boundary: signature=%#v chain=%#v publisher=%#v", signaturePlan, chainPlan, publisherPlan)
			}
		})
	}
}

func TestAuthorizeCatalogPublisherRejectsNilAndCancelledContext(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	var nilContext context.Context
	if _, _, _, _, _, _, err := AuthorizeCatalogPublisher(nilContext, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, _, _, err := AuthorizeCatalogPublisher(ctx, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
	if _, _, _, _, _, _, err := AuthorizeCatalogPublisher(context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, time.Time{}, policy); err == nil || !strings.Contains(err.Error(), "evaluation time is zero") {
		t.Fatalf("zero evaluation time error=%v", err)
	}
}

func FuzzValidateCatalogPublisherPolicyDoesNotPanic(f *testing.F) {
	f.Add("publisher.policy", strings.Repeat("0", 64))
	f.Fuzz(func(t *testing.T, policyID, fingerprint string) {
		policy := CatalogPublisherPolicy{
			Schema:      catalogPublisherPolicySchema,
			Purpose:     catalogPublisherPolicyPurpose,
			PolicyID:    policyID,
			Version:     1,
			GeneratedAt: catalogChainEvaluationTime.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:   catalogChainEvaluationTime.Add(time.Hour).Format(time.RFC3339),
			Rules: []CatalogPublisherRule{{
				ID:                    "rule",
				IdentityKind:          catalogPublisherIdentityCertificate,
				IdentitySHA256:        fingerprint,
				RootID:                "test.root",
				RootCertificateSHA256: strings.Repeat("1", 64),
			}},
		}
		_, _, _ = validateCatalogPublisherPolicy(policy, catalogChainEvaluationTime)
	})
}

func catalogPublisherTestPolicy(fixture catalogChainFixture, identityKind string) CatalogPublisherPolicy {
	identity := certificateFingerprint(fixture.leaf)
	if identityKind == catalogPublisherIdentitySPKI {
		digest := sha256.Sum256(fixture.leaf.RawSubjectPublicKeyInfo)
		identity = hex.EncodeToString(digest[:])
	}
	return CatalogPublisherPolicy{
		Schema:      catalogPublisherPolicySchema,
		Purpose:     catalogPublisherPolicyPurpose,
		PolicyID:    "test.publisher.policy",
		Version:     1,
		GeneratedAt: catalogChainEvaluationTime.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:   catalogChainEvaluationTime.Add(time.Hour).Format(time.RFC3339),
		Rules: []CatalogPublisherRule{{
			ID:                    "allow-test-publisher",
			IdentityKind:          identityKind,
			IdentitySHA256:        identity,
			RootID:                "test.authenticode.root",
			RootCertificateSHA256: certificateFingerprint(fixture.root),
		}},
	}
}

func cloneCatalogPublisherPolicyForTest(source CatalogPublisherPolicy) CatalogPublisherPolicy {
	clone := source
	clone.Rules = append([]CatalogPublisherRule(nil), source.Rules...)
	return clone
}
