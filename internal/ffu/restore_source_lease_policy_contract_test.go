//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestAuthenticatedSourceLeaseProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_source_lease_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"sourcefile.AcquireReadLease",
		"sourcefile.Verify",
		"lease.Context()",
		"lease.Check()",
		"ResolveAuthenticatedSingleStoreV1FullFlash",
		"issuedFullFlashSourceLeaseSeal",
		"KernelReadLeaseRequired:        true",
		"KernelReadLeaseHeld:            true",
		"FallbackAllowed:                false",
		"TargetAccessPermitted:          false",
		"ExecutionSupported:             false",
		"caller-owned source descriptor",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("authenticated FFU source-lease source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"sourcefile.ErrReadLeaseUnavailable",
		"sourcefile.ErrReadLeaseConflict",
		"os.OpenFile(",
		"os.WriteFile(",
		"WriteAt(",
		"internal/device",
		"internal/safety",
		"unix.Open(",
		"syscall.Open(",
		"syscall.Flock(",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"FallbackAllowed:                true",
		"TargetAccessPermitted:          true",
		"ExecutionSupported:             true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("authenticated FFU source-lease source contains forbidden fallback, target, or mutation primitive %q", forbidden)
		}
	}
}
