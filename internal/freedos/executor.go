package freedos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const ExecutionReportSchema = 1

type ExecutionStatus string

type ExecutionPhase string

const (
	ExecutionStatusSucceeded ExecutionStatus = "succeeded"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCancelled ExecutionStatus = "cancelled"

	ExecutionPhasePlan     ExecutionPhase = "plan"
	ExecutionPhasePrepare  ExecutionPhase = "prepare"
	ExecutionPhaseWrite    ExecutionPhase = "write"
	ExecutionPhaseFlush    ExecutionPhase = "flush"
	ExecutionPhaseReadback ExecutionPhase = "readback"
	ExecutionPhaseFinish   ExecutionPhase = "finish"
	ExecutionPhaseComplete ExecutionPhase = "complete"
)

// ExecutionBackend supplies the privileged, identity-bound mechanics while the
// state machine retains ordering, cancellation, changed-media reporting, full
// streaming output, and complete readback requirements. Implementations must
// keep the target descriptor and exclusive lock alive until Close returns.
type ExecutionBackend interface {
	Prepare(context.Context, DevicePlan) error
	BeforeDestructive(context.Context, DevicePlan) error
	TargetWriter() io.Writer
	Flush(context.Context, DevicePlan) error
	TargetReaderAt() io.ReaderAt
	Finish(context.Context, DevicePlan) error
	Close() error
}

// ExecutionOptions carries deterministic time and progress hooks. Progress
// failures are treated exactly like cancellation or I/O failures after the
// bytes already accepted by the target.
type ExecutionOptions struct {
	Now      func() time.Time
	Progress func(uint64) error
}

// ExecutionReport is conservative: MediaChanged becomes true immediately
// before the first destructive backend call and remains true after every error.
// Reusable is true only after complete synchronized byte-for-byte readback and
// the backend's final identity check.
type ExecutionReport struct {
	Schema        int             `json:"schema"`
	Status        ExecutionStatus `json:"status"`
	Phase         ExecutionPhase  `json:"phase"`
	Plan          DevicePlan      `json:"plan"`
	StartedAt     time.Time       `json:"started_at"`
	CompletedAt   time.Time       `json:"completed_at"`
	BytesWritten  uint64          `json:"bytes_written"`
	SHA256        string          `json:"sha256,omitempty"`
	MediaChanged  bool            `json:"media_changed"`
	Verified      bool            `json:"verified"`
	Reusable      bool            `json:"reusable"`
	FailureReason string          `json:"failure_reason,omitempty"`
}

// ExecuteDevicePlan runs a previously reviewed plan through a backend. It does
// not itself discover or open a device; the backend must enforce those kernel-
// backed safety duties in Prepare, BeforeDestructive, Finish, and Close.
func ExecuteDevicePlan(ctx context.Context, plan DevicePlan, backend ExecutionBackend, options ExecutionOptions) (ExecutionReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	report := ExecutionReport{
		Schema:    ExecutionReportSchema,
		Status:    ExecutionStatusFailed,
		Phase:     ExecutionPhasePlan,
		Plan:      plan,
		StartedAt: now().UTC(),
	}
	if err := ValidateDevicePlan(plan); err != nil {
		return finishExecutionReport(report, now, err)
	}
	if backend == nil {
		return finishExecutionReport(report, now, errors.New("FreeDOS execution backend is required"))
	}
	if _, err := NewMediaImageSource(plan.Media); err != nil {
		return finishExecutionReport(report, now, fmt.Errorf("prepare deterministic FreeDOS source: %w", err))
	}

	report.Phase = ExecutionPhasePrepare
	if err := ctx.Err(); err != nil {
		return finishExecutionReport(report, now, err)
	}
	if err := backend.Prepare(ctx, plan); err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("prepare FreeDOS target: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	if err := backend.BeforeDestructive(ctx, plan); err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("final pre-destructive FreeDOS safety check: %w", err))
	}

	report.Phase = ExecutionPhaseWrite
	report.MediaChanged = true
	writer := backend.TargetWriter()
	if writer == nil {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS backend returned no target writer"))
	}
	writeResult, err := StreamMediaImage(ctx, writer, plan.Media, options.Progress)
	report.BytesWritten = writeResult.BytesWritten
	if err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("write FreeDOS media: %w", err))
	}
	if writeResult.BytesWritten != plan.DeviceSizeBytes || writeResult.SHA256 == "" {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS writer did not complete the reviewed device size"))
	}
	report.SHA256 = writeResult.SHA256

	report.Phase = ExecutionPhaseFlush
	if err := ctx.Err(); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	if err := backend.Flush(ctx, plan); err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("flush FreeDOS target: %w", err))
	}

	report.Phase = ExecutionPhaseReadback
	reader := backend.TargetReaderAt()
	if reader == nil {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS backend returned no target readback"))
	}
	readback, err := VerifyMediaReadback(ctx, reader, plan.Media)
	if err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("verify FreeDOS readback: %w", err))
	}
	if readback.BytesWritten != report.BytesWritten || readback.SHA256 != report.SHA256 {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS readback digest differs from the completed write"))
	}
	report.Verified = true

	report.Phase = ExecutionPhaseFinish
	if err := ctx.Err(); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	if err := backend.Finish(ctx, plan); err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("finalize FreeDOS target: %w", err))
	}
	if err := backend.Close(); err != nil {
		return finishExecutionReport(report, now, fmt.Errorf("close FreeDOS target: %w", err))
	}

	report.Status = ExecutionStatusSucceeded
	report.Phase = ExecutionPhaseComplete
	report.Reusable = true
	report.FailureReason = ""
	report.CompletedAt = now().UTC()
	return report, nil
}

func closeExecutionBackend(report ExecutionReport, now func() time.Time, backend ExecutionBackend, runErr error) (ExecutionReport, error) {
	closeErr := backend.Close()
	if closeErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("close FreeDOS target: %w", closeErr))
	}
	return finishExecutionReport(report, now, runErr)
}

func finishExecutionReport(report ExecutionReport, now func() time.Time, err error) (ExecutionReport, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		report.Status = ExecutionStatusCancelled
	} else {
		report.Status = ExecutionStatusFailed
	}
	report.Reusable = false
	report.CompletedAt = now().UTC()
	if err != nil {
		report.FailureReason = err.Error()
	}
	return report, err
}
