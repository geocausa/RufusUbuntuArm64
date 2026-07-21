//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// finishDeviceExecution preserves the state of a destructive formatter run when
// releasing the final target descriptor or lock fails. A populated report must
// not disappear after the medium has already changed.
func finishDeviceExecution(report Report, runErr, closeErr error, now func() time.Time) (Report, error) {
	if closeErr == nil {
		return report, runErr
	}
	closeFailure := fmt.Errorf("close formatter target: %w", closeErr)
	combined := closeFailure
	if runErr != nil {
		combined = errors.Join(runErr, closeFailure)
	}
	if report.Schema == 0 {
		return report, combined
	}
	if now == nil {
		now = time.Now
	}

	report.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	report.Reusable = false
	report.Filesystem = nil
	if runErr == nil {
		report.Status = StatusFailed
		report.Failure = &Failure{
			Phase:        PhaseComplete,
			Message:      closeFailure.Error(),
			MediaChanged: report.MediaChanged,
		}
	} else {
		if report.Status != StatusFailed && report.Status != StatusCancelled {
			report.Status = StatusFailed
			if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
				report.Status = StatusCancelled
			}
		}
		phase := PhaseComplete
		if report.Failure != nil && validFailurePhase(report.Failure.Phase) {
			phase = report.Failure.Phase
		}
		report.Failure = &Failure{
			Phase:        phase,
			Message:      combined.Error(),
			MediaChanged: report.MediaChanged,
		}
	}
	if err := ValidateReport(report); err != nil {
		return Report{}, errors.Join(combined, fmt.Errorf("build formatter close-failure report: %w", err))
	}
	return report, combined
}
