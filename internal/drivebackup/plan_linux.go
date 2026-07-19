//go:build linux

package drivebackup

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"syscall"
)

// DestinationInfo is the stable, read-only output of destination planning.
// CaptureDevice repeats every check immediately before opening the source.
type DestinationInfo struct {
	Path           string `json:"path"`
	Directory      string `json:"directory"`
	RequiredBytes  uint64 `json:"required_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

// InspectDestination validates a prospective output without opening the source
// device. It binds the checks to one no-follow directory descriptor, then closes
// that descriptor before returning the informational plan.
func InspectDestination(outputPath, sourcePath string, required uint64) (DestinationInfo, error) {
	if required == 0 {
		return DestinationInfo{}, errors.New("backup size must be greater than zero")
	}
	if required > math.MaxInt64 {
		return DestinationInfo{}, errors.New("backup size exceeds the supported offset range")
	}
	plan, err := prepareDestination(outputPath, sourcePath, required)
	if err != nil {
		return DestinationInfo{}, err
	}
	defer plan.directory.Close()
	available, err := availableBytes(plan.directory.Fd())
	if err != nil {
		return DestinationInfo{}, err
	}
	return DestinationInfo{
		Path:           plan.path,
		Directory:      filepath.Dir(plan.path),
		RequiredBytes:  required,
		AvailableBytes: available,
	}, nil
}

func availableBytes(fd uintptr) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(fd), &stat); err != nil {
		return 0, fmt.Errorf("inspect backup destination free space: %w", err)
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("backup destination reported an invalid filesystem block size")
	}
	blockSize := uint64(stat.Bsize)
	availableBlocks := uint64(stat.Bavail)
	if availableBlocks > math.MaxUint64/blockSize {
		return math.MaxUint64, nil
	}
	return availableBlocks * blockSize, nil
}
