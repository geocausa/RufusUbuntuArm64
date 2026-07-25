//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestTrustActivationProductionSourceKeepsLaterPolicyGatesOut(t *testing.T) {
	data, err := os.ReadFile("trust_activation_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{
		"x509.NewCertPool",
		"x509.SystemCertPool",
		"AppendCertsFromPEM",
		"net/http",
		"CertificateChainBuilt = true",
		"PublisherTrusted = true",
		"os.WriteFile(",
		"writeTrustStoreFile(",
		"writeTrustStoreTemporary(",
		"trustStoreRenameNoReplace(",
		"trustStoreRenameExchange(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("activation production source contains forbidden later-gate or write primitive %q", forbidden)
		}
	}
	if !strings.Contains(source, "active bundle is withdrawn") {
		t.Fatal("activation production source does not fail closed on withdrawal tombstones")
	}
}
