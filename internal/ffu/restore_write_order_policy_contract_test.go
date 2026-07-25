//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestSinglePhaseWriteOrderProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_write_order_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"PlanSinglePhaseFullFlashWriteOrder",
		"validateRestoreTargetPlan(target)",
		"validateFullFlashValidationPlan(full)",
		"descriptor.PlanSHA256 != descriptorPlanDigest(descriptor)",
		"initial and flash-only ranges must both be absent",
		"final table range to cover the complete sequential payload",
		"DeclaredDescriptorOrderPreserved: true",
		"ConfirmationStillRequired:        true",
		"MutationPermitted:                false",
		"ExecutionSupported:               false",
		"staged-GPT and mobile-style FFU profiles remain refused",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU write-order source is missing required boundary %q", required)
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
		"MutationPermitted:                true",
		"ExecutionSupported:               true",
		"func (plan *FullFlashWriteOrderPlan) Target(",
		"func (plan *FullFlashWriteOrderPlan) Source(",
		"func (plan *FullFlashWriteOrderPlan) File(",
		"func (plan *FullFlashWriteOrderPlan) Write(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU write-order source contains forbidden mutation, descriptor, or privilege primitive %q", forbidden)
		}
	}
}
