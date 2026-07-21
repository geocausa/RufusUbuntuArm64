//go:build linux

package devicequal

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func passedQualificationReport() Report {
	return Report{Schema: 1, Status: StatusPassed}
}

func TestFinishDeviceRunDowngradesPassedReportOnFinalValidationFailure(t *testing.T) {
	validationErr := errors.New("final identity check failed")
	report, err := finishDeviceRun(passedQualificationReport(), validationErr, nil)
	if !errors.Is(err, validationErr) {
		t.Fatalf("final validation error was lost: %v", err)
	}
	if report.Status != StatusFailed || report.Failure == nil || report.Failure.Kind != "finalize" {
		t.Fatalf("passed report was not downgraded: %+v", report)
	}
	if !strings.Contains(report.Failure.Message, validationErr.Error()) {
		t.Fatalf("structured failure omitted validation error: %+v", report.Failure)
	}
}

func TestFinishDeviceRunDowngradesPassedReportOnCloseFailure(t *testing.T) {
	closeErr := errors.New("delayed device error")
	report, err := finishDeviceRun(passedQualificationReport(), nil, closeErr)
	if err == nil || !strings.Contains(err.Error(), "close qualification target") {
		t.Fatalf("close failure was not returned: %v", err)
	}
	if report.Status != StatusFailed || report.Failure == nil || report.Failure.Kind != "close" {
		t.Fatalf("passed report was not downgraded: %+v", report)
	}
}

func TestFinishDeviceRunPreservesExistingFailureAndPassDetails(t *testing.T) {
	failure := &Failure{Kind: "write", RegionIndex: 2, Message: "write failed"}
	report := Report{
		Schema:  1,
		Status:  StatusFailed,
		Failure: failure,
		Passes:  []PassReport{{Number: 1, Pattern: "address-a", Failure: failure}},
	}
	closeErr := errors.New("close failed")

	result, err := finishDeviceRun(report, ErrVerification, closeErr)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("qualification failure identity was lost: %v", err)
	}
	if result.Status != StatusFailed || result.Failure != failure || result.Passes[0].Failure != failure {
		t.Fatalf("failed report or pass state changed: %+v", result)
	}
	if !strings.Contains(result.Failure.Message, "close qualification target") {
		t.Fatalf("structured failure omitted close failure: %+v", result.Failure)
	}
}

func TestFinishDeviceRunPreservesCancellationAndJoinsCloseFailure(t *testing.T) {
	failure := &Failure{Kind: "cancelled", RegionIndex: -1, Message: context.Canceled.Error()}
	report := Report{Schema: 1, Status: StatusCancelled, Failure: failure}
	closeErr := errors.New("close failed")

	result, err := finishDeviceRun(report, context.Canceled, closeErr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity was lost: %v", err)
	}
	if result.Status != StatusCancelled || result.Failure != failure {
		t.Fatalf("cancelled report state changed: %+v", result)
	}
	if !strings.Contains(result.Failure.Message, "close qualification target") {
		t.Fatalf("structured cancellation omitted close failure: %+v", result.Failure)
	}
}

func TestFinishDeviceRunLeavesZeroSchemaPreflightUnstructured(t *testing.T) {
	closeErr := errors.New("close failed")
	report, err := finishDeviceRun(Report{}, errors.New("preflight failed"), closeErr)
	if err == nil || report.Schema != 0 || report.Failure != nil {
		t.Fatalf("preflight result was unexpectedly structured: report=%+v err=%v", report, err)
	}
}
