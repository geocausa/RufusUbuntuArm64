//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestDestructiveConfirmationProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_confirmation_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"targetSession.Check()",
		"targetSession.Evidence()",
		"subtle.ConstantTimeCompare",
		"expectedFullFlashConfirmationPhrase",
		"RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES",
		"issuedFullFlashConfirmationSeal",
		"ConfirmationExactMatch:         true",
		"ConfirmationConsumed:           true",
		"SourceLeaseHeld:                true",
		"TargetSessionHeld:              true",
		"TargetAccessAcquired:           true",
		"GuardedUnmountPerformed:        false",
		"MutationPermitted:              false",
		"ExecutionSupported:             false",
		"exposes no source or target descriptor and no mutation API",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU destructive-confirmation source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.WriteFile(",
		"WriteAt(",
		"func (confirmation *FullFlashDestructiveConfirmation) Target(",
		"func (confirmation *FullFlashDestructiveConfirmation) Source(",
		"func (confirmation *FullFlashDestructiveConfirmation) File(",
		"func (confirmation *FullFlashDestructiveConfirmation) Write(",
		"func (confirmation *FullFlashDestructiveConfirmation) WriteAt(",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"GuardedUnmountPerformed:        true",
		"MutationPermitted:              true",
		"ExecutionSupported:             true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU destructive-confirmation source contains forbidden target, mutation, or privilege primitive %q", forbidden)
		}
	}
}
