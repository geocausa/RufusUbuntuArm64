//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestTrustWithdrawalProductionSourcePreservesSafetyBoundaries(t *testing.T) {
	data, err := os.ReadFile("trust_withdrawal_linux.go")
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
		"TrustAnchorsActivated: true",
		"removeTrustStoreExact(rootFile, trustStoreActiveName)",
		"os.Remove(",
		"/dev/",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("signed FFU trust withdrawal source contains forbidden primitive %q", forbidden)
		}
	}
	for _, required := range []string{
		"planAuthenticatedTrustBundleOperationOpen(",
		"trustStoreWithdrawalGenerationPurpose",
		"trustStoreWithdrawnPurpose",
		"trustStoreRenameNoReplace(",
		"trustStoreRenameExchange(",
		"loadVerifiedTrustStoreWithdrawal(",
		"ErrTrustBundleWithdrawn",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signed FFU trust withdrawal source is missing required boundary %q", required)
		}
	}
}
