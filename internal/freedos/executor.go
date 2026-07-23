package freedos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const ExecutionReportSchema = 2

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
// state machine retains ordering, cancellation, changed-media reporting,
// offset-bound output, and required-extent readback. Implementations must keep
// the target descriptor and exclusive lock alive until Close returns.
type ExecutionBackend interface {
	Prepare(context.Context, DevicePlan) error
	BeforeDestructive(context.Context, DevicePlan) error
	TargetWriterAt() io.WriterAt
	Flush(context.Context, DevicePlan) error
	TargetReaderAt() io.ReaderAt
	Finish(context.Context, DevicePlan) error
	Close() error
}

// ExecutionProgress reports one bounded execution phase. Processed and Total
// describe the current byte-bearing phase; phases without byte accounting use
// zero for both values.
type ExecutionProgress struct {
	Phase     ExecutionPhase `json:"phase"`
	Processed uint64         `json:"processed"`
	Total     uint64         `json:"total"`
}

// ExecutionOptions carries deterministic time and progress hooks. Progress
// failures are treated exactly like cancellation or I/O failures after the
// bytes already accepted by the target.
type ExecutionOptions struct {
	Now           func() time.Time
	Progress      func(uint64) error
	PhaseProgress func(ExecutionProgress) error
}

func emitExecutionProgress(options ExecutionOptions, phase ExecutionPhase, processed, total uint64) error {
	if options.PhaseProgress == nil {
		return nil
	}
	return options.PhaseProgress(ExecutionProgress{Phase: phase, Processed: processed, Total: total})
}

// ExecutionReport is conservative: MediaChanged becomes true immediately
// before the first destructive backend call and remains true after every error.
// Reusable is true only after synchronized required-extent readback and the
// backend's final identity check.
type ExecutionReport struct {
	Schema            int             `json:"schema"`
	Status            ExecutionStatus `json:"status"`
	Phase             ExecutionPhase  `json:"phase"`
	Plan              DevicePlan      `json:"plan"`
	StartedAt         time.Time       `json:"started_at"`
	CompletedAt       time.Time       `json:"completed_at"`
	BytesWritten      uint64          `json:"bytes_written"`
	BytesVerified     uint64          `json:"bytes_verified"`
	VerificationScope string          `json:"verification_scope"`
	SHA256            string          `json:"sha256,omitempty"`
	MediaChanged      bool            `json:"media_changed"`
	Verified          bool            `json:"verified"`
	Reusable          bool            `json:"reusable"`
	FailureReason     string          `json:"failure_reason,omitempty"`
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
		Schema:            ExecutionReportSchema,
		Status:            ExecutionStatusFailed,
		Phase:             ExecutionPhasePlan,
		Plan:              plan,
		StartedAt:         now().UTC(),
		VerificationScope: MediaVerificationScope,
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
	if plan.MutationBytes == 0 || plan.VerificationBytes == 0 {
		return finishExecutionReport(report, now, errors.New("FreeDOS required extent totals are empty"))
	}

	report.Phase = ExecutionPhasePrepare
	if err := emitExecutionProgress(options, report.Phase, 0, 0); err != nil {
		return finishExecutionReport(report, now, err)
	}
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
	if err := emitExecutionProgress(options, report.Phase, 0, plan.MutationBytes); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	report.MediaChanged = true
	writer := backend.TargetWriterAt()
	if writer == nil {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS backend returned no offset-bound target writer"))
	}
	writeProgress := func(completed uint64) error {
		if options.Progress != nil {
			if err := options.Progress(completed); err != nil {
				return err
			}
		}
		return emitExecutionProgress(options, ExecutionPhaseWrite, completed, plan.MutationBytes)
	}
	writeResult, err := WriteMediaExtents(ctx, writer, plan.Media, writeProgress)
	report.BytesWritten = writeResult.BytesWritten
	if err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("write required FreeDOS extents: %w", err))
	}
	if writeResult.BytesWritten != plan.MutationBytes || writeResult.SHA256 == "" {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS writer did not complete the reviewed required extents"))
	}
	report.SHA256 = writeResult.SHA256

	report.Phase = ExecutionPhaseFlush
	if err := emitExecutionProgress(options, report.Phase, 0, 0); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	if err := ctx.Err(); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	if err := backend.Flush(ctx, plan); err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("flush FreeDOS target: %w", err))
	}

	report.Phase = ExecutionPhaseReadback
	if err := emitExecutionProgress(options, report.Phase, 0, plan.VerificationBytes); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
	reader := backend.TargetReaderAt()
	if reader == nil {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS backend returned no target readback"))
	}
	readback, err := VerifyMediaExtents(ctx, reader, plan.Media, func(completed uint64) error {
		return emitExecutionProgress(options, ExecutionPhaseReadback, completed, plan.VerificationBytes)
	})
	report.BytesVerified = readback.BytesWritten
	if err != nil {
		return closeExecutionBackend(report, now, backend, fmt.Errorf("verify required FreeDOS extents: %w", err))
	}
	if readback.BytesWritten != plan.VerificationBytes || readback.SHA256 != report.SHA256 {
		return closeExecutionBackend(report, now, backend, errors.New("FreeDOS required-extent readback digest differs from the completed write"))
	}
	report.Verified = true

	report.Phase = ExecutionPhaseFinish
	if err := emitExecutionProgress(options, report.Phase, 0, 0); err != nil {
		return closeExecutionBackend(report, now, backend, err)
	}
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
