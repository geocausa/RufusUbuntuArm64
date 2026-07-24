package ffu

import (
	"strings"
	"testing"
)

func TestCatalogSignaturePolicyRejectsEveryLegacySHA1SignerForm(t *testing.T) {
	if _, _, err := calculateCatalogContentDigest(oidSHA1, []byte("catalog content")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("legacy SHA-1 content digest was not refused: %v", err)
	}
	for _, signatureOID := range []string{oidRSAEncryption, oidSHA1WithRSA} {
		if _, _, err := catalogSignatureAlgorithm(oidSHA1, signatureOID); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("legacy SHA-1 signature form %s was not refused: %v", signatureOID, err)
		}
	}
}
