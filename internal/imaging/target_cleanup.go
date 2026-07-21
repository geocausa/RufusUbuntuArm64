package imaging

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// finishWriteTarget releases the exclusive raw-writer lock and closes the
// target descriptor without discarding an earlier write or cancellation error.
// A cleanup failure is part of the operation result because close can surface
// delayed device I/O errors after the final Sync.
func finishWriteTarget(runErr error, target *os.File, locked bool) error {
	if target == nil {
		return runErr
	}
	var cleanupErr error
	if locked {
		if err := syscall.Flock(int(target.Fd()), syscall.LOCK_UN); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unlock target after writing: %w", err))
		}
	}
	if err := target.Close(); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close target after writing: %w", err))
	}
	return errors.Join(runErr, cleanupErr)
}
