//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestAuthenticatedIntegrityProductionSourceKeepsLaterGatesOut(t *testing.T) {
	data, err := os.ReadFile("authenticated_integrity_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"AuthorizeCatalogPublisher",
		"VerifyHashTableContent",
		"PlanSingleStoreV1",
		"HashTableCatalogAuthenticated:  true",
		"IntegrityAuthenticated:          true",
		"RevocationChecked:               false",
		"TimestampVerified:               false",
		"ExecutionSupported:              false",
		"TargetSizeBindingRequired:       descriptorPlan.TargetSizeBindingRequired",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("authenticated-integrity source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"x509.SystemCertPool",
		"AppendCertsFromPEM",
		"net/http",
		"http.Get",
		"os.Open(",
		"os.WriteFile(",
		"WriteAt(",
		"targetPath",
		"ExecutionSupported:              true",
		"RevocationChecked:               true",
		"TimestampVerified:               true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("authenticated-integrity source contains forbidden later-gate or I/O primitive %q", forbidden)
		}
	}
}
