//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestCatalogPublisherProductionSourceKeepsLaterGatesOut(t *testing.T) {
	data, err := os.ReadFile("catalog_publisher_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"ffu-catalog-publisher-policy",
		"certificate_sha256",
		"subject_public_key_info_sha256",
		"signaturePlan.PublisherTrusted = true",
		"chainPlan.PublisherTrusted = true",
		"ExplicitPublisherPolicyUsed:   true",
		"PublisherTrusted:              true",
		"HostTLSStoreConsulted:         false",
		"RevocationChecked:             false",
		"TimestampVerified:             false",
		"HashTableCatalogAuthenticated: false",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("catalog-publisher production source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"x509.SystemCertPool",
		"AppendCertsFromPEM",
		"net/http",
		"http.Get",
		"RevocationChecked:             true",
		"TimestampVerified:             true",
		"HashTableCatalogAuthenticated: true",
		"os.Open(",
		"os.WriteFile(",
		"WriteAt(",
		"targetPath",
		"defaultPublisherPolicy",
		"productionPublisherPolicy",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("catalog-publisher production source contains forbidden later-gate, default-policy, or I/O primitive %q", forbidden)
		}
	}
}

func TestCatalogPublisherPolicyHasNoImplicitRootOnlyAcceptance(t *testing.T) {
	data, err := os.ReadFile("catalog_publisher_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"len(policy.Rules) == 0",
		"rule.RootID != chain.SelectedRootID",
		"rule.RootCertificateSHA256 != chain.SelectedRootSHA256",
		"FFU catalog publisher is not authorized by the explicit publisher policy",
		"FFU catalog publisher authorization is ambiguous",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("catalog-publisher source permits implicit or ambiguous publisher acceptance: missing %q", required)
		}
	}
}
