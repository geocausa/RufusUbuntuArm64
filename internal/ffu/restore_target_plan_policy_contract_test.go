//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestRestoreTargetPlanProductionSourceKeepsProviderOut(t *testing.T) {
	data, err := os.ReadFile("restore_target_plan_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"AuthenticateSingleStoreV1Integrity",
		"ExpectedTargetIdentity",
		"TargetIdentityBound:              true",
		"TargetGeometryBound:              true",
		"DestinationMapResolved:           true",
		"ValidationChecksResolved:         false",
		"ExecutionSupported:               false",
		"RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("restore target-plan source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.WriteFile(",
		"WriteAt(",
		"unix.Open(",
		"syscall.Open(",
		"net/http",
		"http.Get",
		"ExecutionSupported:               true",
		"ValidationChecksResolved:         true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("restore target-plan source contains forbidden provider or I/O primitive %q", forbidden)
		}
	}
}
