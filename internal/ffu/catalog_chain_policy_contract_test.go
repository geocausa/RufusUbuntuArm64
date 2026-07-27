//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestCatalogChainProductionSourceKeepsLaterTrustGatesOut(t *testing.T) {
	data, err := os.ReadFile("catalog_chain_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"x509.NewCertPool",
		"x509.ExtKeyUsageCodeSigning",
		"x509.KeyUsageDigitalSignature",
		"x509.KeyUsageCertSign",
		"activation.capability",
		"CertificateChainBuilt:         true",
		"HostTLSStoreConsulted:         false",
		"RevocationChecked:             false",
		"TimestampVerified:             false",
		"PublisherTrusted:              false",
		"HashTableCatalogAuthenticated: false",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("catalog-chain production source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"x509.SystemCertPool",
		"AppendCertsFromPEM",
		"net/http",
		"http.Get",
		"PublisherTrusted:              true",
		"HashTableCatalogAuthenticated: true",
		"RevocationChecked:             true",
		"TimestampVerified:             true",
		"os.Open(",
		"os.WriteFile(",
		"WriteAt(",
		"targetPath",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("catalog-chain production source contains forbidden later-gate or I/O primitive %q", forbidden)
		}
	}
}

func TestTrustActivationCapabilitySealIsNotExportedOrSerialized(t *testing.T) {
	data, err := os.ReadFile("trust_activation_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if !strings.Contains(source, "capability               *trustBundleActivationCapability") || !strings.Contains(source, "activation.capability = &trustBundleActivationCapability{activationSHA256: activation.ActivationSHA256}") {
		t.Fatal("trust activation does not carry the verified immutable capability seal")
	}
	if strings.Contains(source, "capability               *trustBundleActivationCapability `json:") {
		t.Fatal("trust activation capability seal became caller-serializable")
	}
}
