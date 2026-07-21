//go:build linux

package persistence

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// finishPersistenceFile releases an optional exclusive lock and closes one
// persistence descriptor without discarding an earlier operation or
// cancellation error. Close failures remain part of the final result because
// they can surface delayed partition I/O errors after synchronization.
func finishPersistenceFile(runErr error, file *os.File, locked bool, description string) error {
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

// emitFilesystemCompletion publishes success only after every deferred mount,
// workspace, lock, and descriptor finalizer has completed cleanly.
func emitFilesystemCompletion(completed bool, runErr error, event func(FilesystemEvent)) {
	if !completed || runErr != nil {
		return
	}
	emitFilesystem(event, "complete", "Persistence filesystem created and checked.")
}
