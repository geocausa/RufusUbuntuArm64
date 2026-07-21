//go:build linux

package acquisition

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	atFDCWD             = ^uintptr(99)
	renameNoReplaceFlag = uintptr(1)
)

func renameDownloadedFileNoReplace(source, destination string) error {
	sourcePointer, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.BytePtrFromString(destination)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		renameat2Trap,
		atFDCWD,
		uintptr(unsafe.Pointer(sourcePointer)),
		atFDCWD,
		uintptr(unsafe.Pointer(destinationPointer)),
		renameNoReplaceFlag,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(destinationPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
