//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFinishDeviceExecutionDowngradesSuccessOnCloseFailure(t *testing.T) {
	plan := executorPlan(t)
	report, runErr := Execute(context.Background(), plan, successfulBackend(plan), fixedClock())
	if runErr != nil {
		t.Fatal(runErr)
	}
	closeErr := errors.New("descriptor close failed")
	finished, err := finishDeviceExecution(report, nil, closeErr, fixedClock())
	if !errors.Is(err, closeErr) {
		t.Fatalf("error=%v, want close failure", err)
	}
	if finished.Schema == 0 || finished.Status != StatusFailed || !finished.MediaChanged || finished.Reusable || finished.Filesystem != nil {
		t.Fatalf("close failure discarded or contradicted formatter state: %+v", finished)
	}
	if finished.Failure == nil || finished.Failure.Phase != PhaseComplete || !strings.Contains(finished.Failure.Message, closeErr.Error()) {
		t.Fatalf("close failure was not preserved in the report: %+v", finished.Failure)
	}
	if err := ValidateReport(finished); err != nil {
		t.Fatalf("close-failure report is invalid: %v", err)
	}
}

func TestFinishDeviceExecutionJoinsCloseFailureIntoFailedReport(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	backend.failPhase = PhaseFormat
	report, runErr := Execute(context.Background(), plan, backend, fixedClock())
	if runErr == nil {
		t.Fatal("format failure was not produced")
	}
	closeErr := errors.New("unlock failed")
	finished, err := finishDeviceExecution(report, runErr, closeErr, fixedClock())
	if !errors.Is(err, runErr) || !errors.Is(err, closeErr) {
		t.Fatalf("combined error=%v, want run and close failures", err)
	}
	if finished.Status != StatusFailed || finished.Failure == nil || finished.Failure.Phase != PhaseFormat {
		t.Fatalf("original failure status or phase was lost: %+v", finished)
	}
	if !strings.Contains(finished.Failure.Message, runErr.Error()) || !strings.Contains(finished.Failure.Message, closeErr.Error()) {
		t.Fatalf("structured failure did not include both errors: %q", finished.Failure.Message)
	}
	if err := ValidateReport(finished); err != nil {
		t.Fatalf("combined failure report is invalid: %v", err)
	}
}

func TestFinishDeviceExecutionPreservesCancellationOnCloseFailure(t *testing.T) {
	plan := executorPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	backend := successfulBackend(plan)
	backend.cancelAfter = PhaseErase
	backend.cancel = cancel
	report, runErr := Execute(ctx, plan, backend, fixedClock())
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("error=%v, want cancellation", runErr)
	}
	closeErr := errors.New("close after cancellation failed")
	finished, err := finishDeviceExecution(report, runErr, closeErr, fixedClock())
	if !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
		t.Fatalf("combined error=%v, want cancellation and close failure", err)
	}
	if finished.Status != StatusCancelled || finished.Failure == nil || finished.Failure.Phase != PhasePartition || !finished.MediaChanged {
		t.Fatalf("cancellation state was not preserved: %+v", finished)
	}
	if err := ValidateReport(finished); err != nil {
		t.Fatalf("cancelled close-failure report is invalid: %v", err)
	}
}
