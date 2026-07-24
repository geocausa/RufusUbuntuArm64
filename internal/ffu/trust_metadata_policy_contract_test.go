package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestTrustMetadataProductionContainsNoPrivateSigningKeyMaterial(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	foundPublicVerification := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{
			"ed25519.PrivateKey",
			"ed25519.NewKeyFromSeed",
			"ed25519.GenerateKey",
			"ed25519.Sign(",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("production file %s contains private signing primitive %q", name, forbidden)
			}
		}
		if strings.Contains(text, "ed25519.Verify(") {
			foundPublicVerification = true
		}
	}
	if !foundPublicVerification {
		t.Fatal("production FFU package no longer performs Ed25519 public-key verification")
	}
}
