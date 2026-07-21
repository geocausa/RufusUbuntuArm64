//go:build linux

package linuxmedia

import "errors"

func alignLayoutChecked(value, alignment uint64) (uint64, error) {
	if alignment == 0 {
		return 0, errors.New("layout alignment is zero")
	}
	remainder := value % alignment
	if remainder == 0 {
		return value, nil
	}
	increment := alignment - remainder
	if value > ^uint64(0)-increment {
		return 0, errors.New("layout alignment overflows byte geometry")
	}
	return value + increment, nil
}
