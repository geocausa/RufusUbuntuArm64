//go:build linux

package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// reopenableDeviceOpenFlags deliberately excludes O_EXCL. Linux filesystem
// tools such as mkfs.vfat and mkfs.ext4 reopen an inherited /proc/self/fd/N
// target with their own exclusive open. Holding the original block-device
// descriptor with O_EXCL makes that trusted reopen fail with EBUSY.
const reopenableDeviceOpenFlags = os.O_RDWR | syscall.O_NOFOLLOW

const (
	exclusiveFlockWait     = 2 * time.Second
	exclusiveFlockInterval = 50 * time.Millisecond
)

// OpenReopenableDevice opens a no-follow read/write descriptor that trusted
// filesystem tools can reopen through an inherited /proc/self/fd/N path.
// Callers must retain their whole-disk lock, take an advisory flock on the
// returned descriptor, and revalidate its identity and geometry.
func OpenReopenableDevice(path string) (*os.File, error) {
	return os.OpenFile(path, reopenableDeviceOpenFlags, 0)
}

// AcquireExclusiveFlock makes bounded nonblocking attempts to acquire an
// advisory device lock. This tolerates short-lived udev or desktop probes while
// still failing closed when another process keeps the target locked.
func AcquireExclusiveFlock(ctx context.Context, file *os.File) error {
	if ctx == nil {
		return errors.New("device lock context is nil")
	}
	if file == nil {
		return errors.New("device file is nil")
	}

	deadline := time.NewTimer(exclusiveFlockWait)
	defer deadline.Stop()
	retry := time.NewTicker(exclusiveFlockInterval)
	defer retry.Stop()

	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return err
		case <-retry.C:
		}
	}
}

// WithTemporarilyReleasedFlock lets a trusted filesystem formatter reopen an
// inherited block-device descriptor with its own exclusive policy. The caller
// must retain the independently locked whole-disk descriptor for the complete
// operation. The partition lock is restored before this function returns.
func WithTemporarilyReleasedFlock(file *os.File, operation func() error) (returnErr error) {
	if file == nil {
		return errors.New("device file is nil")
	}
	if operation == nil {
		return errors.New("device operation is nil")
	}
	fd := int(file.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		return fmt.Errorf("release device lock for trusted formatter: %w", err)
	}
	defer func() {
		if err := AcquireExclusiveFlock(context.Background(), file); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore device lock after trusted formatter: %w", err))
		}
	}()
	return operation()
}
