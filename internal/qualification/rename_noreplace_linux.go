//go:build linux

package qualification

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	atFDCWD         = ^uintptr(99)
	renameNoReplace = uintptr(1)
)

func renameMetadataNoReplace(source, destination string) error {
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
		renameNoReplace,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(destinationPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
