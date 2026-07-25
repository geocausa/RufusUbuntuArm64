//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestTrustUpdateWithdrawalProductionSourcePreservesSecurityBoundaries(t *testing.T) {
	data, err := os.ReadFile("trust_update_withdraw_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{
		"ed25519.Sign(",
		"ed25519.GenerateKey(",
		"ed25519.NewKeyFromSeed(",
		"x509.NewCertPool",
		"x509.SystemCertPool",
		"AppendCertsFromPEM",
		"net/http",
		"ActivateAuthenticatedTrustBundle(",
		"CertificateChainBuilt: true",
		"PublisherTrusted: true",
		"HostTLSStoreConsulted: true",
		"removeTrustStoreExact(rootFile, trustStoreActiveName)",
		"/dev/",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("signed FFU trust withdrawal source contains forbidden primitive %q", forbidden)
		}
	}
	for _, required := range []string{
		"planAuthenticatedTrustBundleOperationOpen(",
		"trustStoreRenameNoReplace(",
		"trustStoreRenameExchange(",
		"loadTrustStoreGeneration(",
		"trustStoreWithdrawalGenerationPurpose",
		"Withdrawn:      true",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signed FFU trust withdrawal source is missing required transaction boundary %q", required)
		}
	}
}
