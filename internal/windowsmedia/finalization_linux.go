//go:build linux

package windowsmedia

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// finishWindowsMediaFile releases an optional exclusive lock and closes one
// Windows-media descriptor without discarding an earlier operation or
// cancellation error. Close failures remain part of the final result because
// they can surface delayed target I/O errors after synchronization.
func finishWindowsMediaFile(runErr error, file *os.File, locked bool, description string) error {
	if file == nil {
		return runErr
	}
	var cleanupErr error
	if locked {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unlock %s: %w", description, err))
		}
	}
	if err := file.Close(); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close %s: %w", description, err))
	}
	return errors.Join(runErr, cleanupErr)
}
