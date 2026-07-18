//go:build linux

package safety

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// reopenableDeviceOpenFlags deliberately excludes O_EXCL. Linux filesystem
// tools such as mkfs.vfat and mkfs.ext4 reopen an inherited /proc/self/fd/N
// target with their own exclusive open. Holding the original block-device
// descriptor with O_EXCL makes that trusted reopen fail with EBUSY.
const reopenableDeviceOpenFlags = os.O_RDWR | syscall.O_NOFOLLOW

// OpenReopenableDevice opens a no-follow read/write descriptor that trusted
// filesystem tools can reopen through an inherited /proc/self/fd/N path.
// Callers must retain their whole-disk lock, take an advisory flock on the
// returned descriptor, and revalidate its identity and geometry.
func OpenReopenableDevice(path string) (*os.File, error) {
	return os.OpenFile(path, reopenableDeviceOpenFlags, 0)
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
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore device lock after trusted formatter: %w", err))
		}
	}()
	return operation()
}
