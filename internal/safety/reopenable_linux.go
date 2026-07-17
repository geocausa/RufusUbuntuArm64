//go:build linux

package safety

import (
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
