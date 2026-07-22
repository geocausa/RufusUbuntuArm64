//go:build linux

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	channelAdminATFDCWD         = ^uintptr(99)
	channelAdminRenameNoReplace = uintptr(1)
)

func channelAdminRenameat2Trap() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 316, nil
	case "arm64":
		return 276, nil
	default:
		return 0, fmt.Errorf("atomic no-replace publication is unsupported on linux/%s", runtime.GOARCH)
	}
}

func renameNoReplace(source, destination string) error {
	trap, err := channelAdminRenameat2Trap()
	if err != nil {
		return err
	}
	sourcePointer, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.BytePtrFromString(destination)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		trap,
		channelAdminATFDCWD,
		uintptr(unsafe.Pointer(sourcePointer)),
		channelAdminATFDCWD,
		uintptr(unsafe.Pointer(destinationPointer)),
		channelAdminRenameNoReplace,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(destinationPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
