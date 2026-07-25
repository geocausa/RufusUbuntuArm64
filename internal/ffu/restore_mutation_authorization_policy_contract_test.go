//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestMutationAuthorizationProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_mutation_authorization_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"AuthorizeSinglePhaseFullFlashMutation",
		"confirmation.Check()",
		"confirmation.Evidence()",
		"PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)",
		"issuedFullFlashMutationAuthorizationSeal",
		"ConfirmationSatisfied:          true",
		"SinglePhaseWriteOrderResolved:  true",
		"StagedGPTProfileAllowed:        false",
		"OneShotExecutionRequired:       true",
		"AuthorizationConsumed:          false",
		"MutationPermitted:              true",
		"ExecutionSupported:             false",
		"exposes no source or target descriptor and no mutation API",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU mutation-authorization source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.WriteFile(",
		"WriteAt(",
		"Pwrite",
		"syscall.",
		"unix.",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"AuthorizationConsumed:          true",
		"ExecutionSupported:             true",
		"func (authorization *FullFlashMutationAuthorization) Target(",
		"func (authorization *FullFlashMutationAuthorization) Source(",
		"func (authorization *FullFlashMutationAuthorization) File(",
		"func (authorization *FullFlashMutationAuthorization) Write(",
		"func (authorization *FullFlashMutationAuthorization) WriteAt(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU mutation-authorization source contains forbidden descriptor, execution, or privilege primitive %q", forbidden)
		}
	}
}
