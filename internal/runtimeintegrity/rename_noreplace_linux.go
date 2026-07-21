//go:build linux

package runtimeintegrity

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const renameNoReplaceFlag = uintptr(1)

func renameNoReplaceAt(directory *os.File, source, destination string) error {
	sourcePointer, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.BytePtrFromString(destination)
	if err != nil {
		return err
	}
	directoryFD := uintptr(directory.Fd())
	_, _, errno := syscall.Syscall6(
		renameat2Trap,
		directoryFD,
		uintptr(unsafe.Pointer(sourcePointer)),
		directoryFD,
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
