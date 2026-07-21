//go:build linux

package devicequal

import (
	"errors"
	"fmt"
)

// finishDeviceRun reconciles errors from the qualification engine, the final
// held-target validation, and target close with the structured report. A report
// must never remain passed when the operation's final target boundary failed.
func finishDeviceRun(report Report, runErr, closeErr error) (Report, error) {
	var cleanupErr error
	if closeErr != nil {
		cleanupErr = fmt.Errorf("close qualification target: %w", closeErr)
	}
	finalErr := errors.Join(runErr, cleanupErr)
	if finalErr == nil || report.Schema == 0 {
		return report, finalErr
	}

	if report.Failure != nil {
		if cleanupErr != nil {
			report.Failure.Message = errors.Join(errors.New(report.Failure.Message), cleanupErr).Error()
		}
		return report, finalErr
	}

	kind := "finalize"
	message := finalErr.Error()
	if runErr == nil {
		kind = "close"
		message = cleanupErr.Error()
	}
	failure := &Failure{
		Kind:        kind,
		RegionIndex: -1,
		Message:     message,
	}
	if report.Status == StatusPassed {
		report.Status = StatusFailed
	}
	report.Failure = failure
	report.AliasingDetected = false
	return report, finalErr
}
