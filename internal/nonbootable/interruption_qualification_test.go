//go:build linux

package nonbootable

import (
	"context"
	"testing"
)

func TestExecuteInterruptionQualificationEveryMutationPhase(t *testing.T) {
	plan := executorPlan(t)
	tests := []struct {
		phase   string
		changed bool
	}{
		{PhasePreflight, false},
		{PhaseErase, true},
		{PhasePartition, true},
		{PhaseFormat, true},
		{PhaseVerify, true},
		{PhaseComplete, true},
	}
	for _, test := range tests {
		t.Run(test.phase, func(t *testing.T) {
			backend := successfulBackend(plan)
			backend.failPhase = test.phase
			report, err := Execute(context.Background(), plan, backend, fixedClock())
			if err == nil {
				t.Fatal("injected formatter failure was reported as success")
			}
			if report.Status == StatusPassed || report.MediaChanged != test.changed || report.Reusable || report.Filesystem != nil {
				t.Fatalf("unsafe formatter interruption report: %+v", report)
			}
			if report.Failure == nil || report.Failure.Phase != test.phase || report.Failure.MediaChanged != test.changed {
				t.Fatalf("incorrect failure evidence: %+v", report.Failure)
			}
		})
	}
}
