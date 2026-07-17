package imaging

import (
	"fmt"
	"math"
)

func checkedImageAdd(label string, current, increment uint64) (uint64, error) {
	if math.MaxUint64-current < increment {
		return 0, fmt.Errorf("%s exceeds the supported 64-bit size range", label)
	}
	return current + increment, nil
}

func requireHostFileSize(label string, size uint64) error {
	if size > uint64(math.MaxInt64) {
		return fmt.Errorf("%s exceeds the host's signed file-offset range", label)
	}
	return nil
}
