//go:build linux

package windowsmedia

import (
	"fmt"
)

const (
	maxWindowsMediaEntries = 300000
	maxDriverFolderEntries = 100000
)

func checkedAdd(label string, values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if ^uint64(0)-total < value {
			return 0, fmt.Errorf("%s exceeds the supported 64-bit size range", label)
		}
		total += value
	}
	return total, nil
}

func checkedMultiply(label string, left, right uint64) (uint64, error) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, fmt.Errorf("%s exceeds the supported 64-bit size range", label)
	}
	return left * right, nil
}

func countBoundedEntry(count *int, limit int, label string) error {
	if count == nil || limit <= 0 {
		return fmt.Errorf("invalid %s traversal limit", label)
	}
	*count++
	if *count > limit {
		return fmt.Errorf("%s contains more than %d entries", label, limit)
	}
	return nil
}
