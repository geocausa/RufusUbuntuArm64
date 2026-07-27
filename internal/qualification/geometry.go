//go:build linux

package qualification

import "errors"

func partitionExtentEnd(start, size uint64) (uint64, error) {
	if size > ^uint64(0)-start {
		return 0, errors.New("partition extent overflows byte geometry")
	}
	return start + size, nil
}
