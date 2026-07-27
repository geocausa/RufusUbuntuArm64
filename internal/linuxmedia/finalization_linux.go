//go:build linux

package linuxmedia

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// finishPersistentFile releases an optional exclusive lock and closes one
// persistent-media descriptor without discarding an earlier operation or
// cancellation error. Close failures remain part of the final result because
// they can surface delayed device I/O errors after synchronization.
func finishPersistentFile(runErr error, file *os.File, locked bool, description string) error {
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

// emitPersistentCompletion publishes success only after every deferred
// workspace, mount, lock, and descriptor finalizer has completed cleanly.
func emitPersistentCompletion(completed bool, runErr error, emit PersistentEventFunc) {
	if !completed || runErr != nil {
		return
	}
	sendPersistent(emit, PersistentEvent{
		Stage:   "complete",
		Message: "Experimental persistent Linux USB created and verified.",
	})
}
