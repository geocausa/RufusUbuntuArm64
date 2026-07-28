//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const extractedTargetLockTimeout = 5 * time.Second

// acquireExtractedTargetLock preserves the non-blocking exclusive flock safety
// boundary while allowing short-lived udev/kernel inspection to finish after a
// removable target appears. Cancellation wins immediately; sustained or
// unexpected contention remains a fail-closed error before target mutation.
func acquireExtractedTargetLock(ctx context.Context, target *os.File, devicePath string) error {
	if ctx == nil {
		return errors.New("ISO Image mode target-lock context is nil")
	}
	if target == nil {
		return errors.New("ISO Image mode target descriptor is nil")
	}
	deadline := time.NewTimer(extractedTargetLockTimeout)
	defer deadline.Stop()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()

	for {
		err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("acquire exclusive ISO Image mode target lock for %s: %w", devicePath, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("acquire exclusive ISO Image mode target lock for %s: %w", devicePath, ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
		case <-retry.C:
		}
	}
}
