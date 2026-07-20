//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeFormatterBackend struct {
	calls           []string
	failPhase       string
	cancelAfter     string
	cancel          context.CancelFunc
	partitionScript string
	state           FilesystemState
}

func (backend *fakeFormatterBackend) step(name string) error {
	backend.calls = append(backend.calls, name)
	if backend.cancelAfter == name && backend.cancel != nil {
		backend.cancel()
	}
	if backend.failPhase == name {
		return errors.New(name + " failed")
	}
	return nil
}

func (backend *fakeFormatterBackend) Prepare(context.Context, Plan, PartitionTable) error {
	return backend.step(PhasePreflight)
}
func (backend *fakeFormatterBackend) Erase(context.Context, Plan, PartitionTable) error {
	return backend.step(PhaseErase)
}
func (backend *fakeFormatterBackend) Partition(_ context.Context, _ Plan, _ PartitionTable, script string) (string, error) {
	backend.partitionScript = script
	if err := backend.step(PhasePartition); err != nil {
		return "", err
	}
	return "/dev/sdb1", nil
}
func (backend *fakeFormatterBackend) Format(context.Context, Plan, PartitionTable, string) error {
	return backend.step(PhaseFormat)
}
func (backend *fakeFormatterBackend) Verify(context.Context, Plan, PartitionTable, string) (FilesystemState, error) {
	if err := backend.step(PhaseVerify); err != nil {
		return FilesystemState{}, err
	}
	return backend.state, nil
}
func (backend *fakeFormatterBackend) Finish(context.Context, Plan, PartitionTable, FilesystemState) error {
	return backend.step(PhaseComplete)
}

func executorPlan(t *testing.T) Plan {
	t.Helper()
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("d", 64),
		DeviceSizeBytes:   8 * 1024 * 1024 * 1024,
		LogicalSectorSize: 512,
		Scheme:            "gpt",
		Filesystem:        "fat32",
		Label:             "DATA",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func fixedClock() func() time.Time {
	value := time.Date(2026, 7, 20, 7, 0, 0, 0, time.UTC)
	return func() time.Time {
		value = value.Add(time.Millisecond)
		return value
	}
}

func successfulBackend(plan Plan) *fakeFormatterBackend {
	return &fakeFormatterBackend{state: FilesystemState{
		Path:       "/dev/sdb1",
		Type:       plan.Filesystem,
		Label:      plan.Label,
		UUID:       "ABCD-1234",
		SizeBytes:  plan.PartitionSizeBytes,
		ParentPath: plan.DevicePath,
	}}
}

func TestExecuteSuccessfulLifecycle(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	report, err := Execute(context.Background(), plan, backend, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusPassed || !report.MediaChanged || !report.Reusable || report.Bootable {
		t.Fatalf("unexpected success report: %+v", report)
	}
	expectedCalls := []string{PhasePreflight, PhaseErase, PhasePartition, PhaseFormat, PhaseVerify, PhaseComplete}
	if strings.Join(backend.calls, ",") != strings.Join(expectedCalls, ",") {
		t.Fatalf("calls=%v, want %v", backend.calls, expectedCalls)
	}
	if !strings.Contains(backend.partitionScript, "name=RUFUSARM64-DATA") {
		t.Fatalf("executor did not pass the deterministic GPT script: %q", backend.partitionScript)
	}
	if err := ValidateReport(report); err != nil {
		t.Fatalf("success report rejected: %v", err)
	}
}

func TestCancellationBeforeEraseReportsUntouchedMedia(t *testing.T) {
	plan := executorPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := successfulBackend(plan)
	report, err := Execute(ctx, plan, backend, fixedClock())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	if report.Status != StatusCancelled || report.MediaChanged || report.Reusable {
		t.Fatalf("unexpected pre-erase cancellation report: %+v", report)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend was called after preflight cancellation: %v", backend.calls)
	}
}

func TestCancellationAfterEraseReportsIncompleteMedia(t *testing.T) {
	plan := executorPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	backend := successfulBackend(plan)
	backend.cancelAfter = PhaseErase
	backend.cancel = cancel
	report, err := Execute(ctx, plan, backend, fixedClock())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	if report.Status != StatusCancelled || !report.MediaChanged || report.Reusable {
		t.Fatalf("unexpected post-erase cancellation report: %+v", report)
	}
	if report.Failure == nil || report.Failure.Phase != PhasePartition {
		t.Fatalf("unexpected cancellation phase: %+v", report.Failure)
	}
	if strings.Join(backend.calls, ",") != PhasePreflight+","+PhaseErase {
		t.Fatalf("unexpected calls after cancellation: %v", backend.calls)
	}
}

func TestEraseErrorConservativelyReportsChangedMedia(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	backend.failPhase = PhaseErase
	report, err := Execute(context.Background(), plan, backend, fixedClock())
	if err == nil {
		t.Fatal("erase failure was ignored")
	}
	if report.Status != StatusFailed || !report.MediaChanged || report.Reusable {
		t.Fatalf("erase failure did not conservatively mark media changed: %+v", report)
	}
	if report.Failure == nil || report.Failure.Phase != PhaseErase || !report.Failure.MediaChanged {
		t.Fatalf("unexpected erase failure details: %+v", report.Failure)
	}
}

func TestBackendContextErrorBecomesCancelledReport(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	backend.failPhase = PhaseFormat
	// Wrap the fake's ordinary failure with context cancellation at the interface
	// boundary to prove status selection uses errors.Is rather than string matching.
	wrapping := &contextFailureBackend{fakeFormatterBackend: backend}
	report, err := Execute(context.Background(), plan, wrapping, fixedClock())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	if report.Status != StatusCancelled || !report.MediaChanged || report.Failure.Phase != PhaseFormat {
		t.Fatalf("unexpected cancelled report: %+v", report)
	}
}

type contextFailureBackend struct{ *fakeFormatterBackend }

func (backend *contextFailureBackend) Format(ctx context.Context, plan Plan, table PartitionTable, path string) error {
	backend.calls = append(backend.calls, PhaseFormat)
	return context.Canceled
}

func TestFinishFailureDoesNotPublishVerifiedFilesystem(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	backend.failPhase = PhaseComplete
	report, err := Execute(context.Background(), plan, backend, fixedClock())
	if err == nil {
		t.Fatal("finish failure was ignored")
	}
	if report.Filesystem != nil || report.Reusable || report.Failure == nil || report.Failure.Phase != PhaseComplete {
		t.Fatalf("finish failure leaked a verified filesystem: %+v", report)
	}
}

func TestValidateReportRejectsContradictions(t *testing.T) {
	plan := executorPlan(t)
	backend := successfulBackend(plan)
	report, err := Execute(context.Background(), plan, backend, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "bootable", mutate: func(value *Report) { value.Bootable = true }},
		{name: "wrong parent", mutate: func(value *Report) { value.Filesystem.ParentPath = "/dev/sdc" }},
		{name: "wrong type", mutate: func(value *Report) { value.Filesystem.Type = "ext4" }},
		{name: "wrong size", mutate: func(value *Report) { value.Filesystem.SizeBytes-- }},
		{name: "success failure", mutate: func(value *Report) { value.Failure = &Failure{Phase: PhaseVerify, Message: "bad", MediaChanged: true} }},
		{name: "completion before start", mutate: func(value *Report) { value.CompletedAt = "2026-07-19T00:00:00Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := report
			state := *report.Filesystem
			copy.Filesystem = &state
			test.mutate(&copy)
			if err := ValidateReport(copy); err == nil {
				t.Fatal("contradictory report was accepted")
			}
		})
	}
}
