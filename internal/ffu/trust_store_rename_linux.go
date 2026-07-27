//go:build linux

package ffu

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	trustStoreRenameNoReplaceFlag = uintptr(1)
	trustStoreRenameExchangeFlag  = uintptr(2)
)

func trustStoreRenameNoReplace(directory *os.File, source, destination string) error {
	return trustStoreRenameAt(directory, source, destination, trustStoreRenameNoReplaceFlag)
}

func trustStoreRenameExchange(directory *os.File, source, destination string) error {
	return trustStoreRenameAt(directory, source, destination, trustStoreRenameExchangeFlag)
}

func trustStoreRenameAt(directory *os.File, source, destination string, flags uintptr) error {
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
		trustStoreRenameat2Trap,
		directoryFD,
		uintptr(unsafe.Pointer(sourcePointer)),
		directoryFD,
		uintptr(unsafe.Pointer(destinationPointer)),
		flags,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(destinationPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
