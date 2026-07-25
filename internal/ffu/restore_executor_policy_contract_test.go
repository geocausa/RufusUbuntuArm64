//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestOneShotExecutorProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_executor_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"ExecuteAuthorizedSinglePhaseFullFlash",
		"authorization.mu.Lock()",
		"confirmation.mu.Lock()",
		"target.mu.Lock()",
		"source.mu.Lock()",
		"revalidateFullFlashExecutionLocked",
		"authorization.consumed = true",
		"source.lease.Check()",
		"sourcefile.Verify(source.file, source.identity)",
		"writeFullFlashAt",
		"ops.syncTarget(target.file)",
		"readback-mismatch",
		"TargetMayBePartiallyModified",
		"CancelledBeforeMutation",
		"CancelledAfterMutation",
		"fullFlashExecutionStatusVerified",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU executor source is missing required transaction boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.Create(",
		"syscall.Open",
		"unix.Open",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"exec.Command",
		"devicePath string",
		"sourcePath string",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU executor source contains forbidden path reopen, unmount, or privilege primitive %q", forbidden)
		}
	}
}
