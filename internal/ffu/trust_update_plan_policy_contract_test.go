//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestTrustUpdatePlannerProductionSourceHasNoMutationOrLaterTrustPrimitive(t *testing.T) {
	data, err := os.ReadFile("trust_update_plan_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{
		"ed25519.Sign(",
		"ed25519.GenerateKey(",
		"ed25519.NewKeyFromSeed(",
		"crypto/x509",
		"x509.NewCertPool",
		"net/http",
		"os.WriteFile(",
		"os.Create(",
		"os.Rename(",
		"os.Remove(",
		"PublishAuthenticatedTrustBundle(",
		"ActivateAuthenticatedTrustBundle(",
		"writeTrustStore",
		"trustStoreRename",
		"removeTrustStore",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU trust update planner production source contains forbidden primitive %q", forbidden)
		}
	}
}
