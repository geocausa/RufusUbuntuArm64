//go:build linux

package drivebackup

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"syscall"
)

// DestinationInfo is the stable, read-only output of destination planning.
// CaptureDevice repeats every check immediately before opening the source.
type DestinationInfo struct {
	Path                  string `json:"path"`
	Directory             string `json:"directory"`
	Format                Format `json:"format"`
	SourceBytes           uint64 `json:"source_bytes"`
	RequiredBytes         uint64 `json:"required_bytes"`
	ContainerMinimumBytes uint64 `json:"container_minimum_bytes,omitempty"`
	AvailableBytes        uint64 `json:"available_bytes"`
}

// InspectDestination preserves the raw-backup planning API.
func InspectDestination(outputPath, sourcePath string, required uint64) (DestinationInfo, error) {
	return InspectDestinationForFormat(context.Background(), outputPath, sourcePath, required, FormatRaw)
}

// InspectDestinationForFormat validates a prospective output without opening
// the source device. Container formats use qemu-img's fully-allocated measure as
// the conservative free-space requirement and report the smaller minimum only
// as informational evidence.
func InspectDestinationForFormat(ctx context.Context, outputPath, sourcePath string, sourceSize uint64, format Format) (DestinationInfo, error) {
	if ctx == nil {
		return DestinationInfo{}, errors.New("backup planning context is nil")
	}
	if sourceSize == 0 {
		return DestinationInfo{}, errors.New("backup size must be greater than zero")
	}
	if sourceSize > math.MaxInt64 {
		return DestinationInfo{}, errors.New("backup size exceeds the supported offset range")
	}
	if format == "" {
		format = FormatRaw
	}
	if !format.Valid() {
		return DestinationInfo{}, fmt.Errorf("unsupported backup format %q", format)
	}
	required := sourceSize
	minimum := uint64(0)
	if format.Container() {
		measure, err := MeasureContainer(ctx, sourceSize, format)
		if err != nil {
			return DestinationInfo{}, err
		}
		required = measure.FullyAllocatedBytes
		minimum = measure.RequiredBytes
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
		Path:                  plan.path,
		Directory:             filepath.Dir(plan.path),
		Format:                format,
		SourceBytes:           sourceSize,
		RequiredBytes:         required,
		ContainerMinimumBytes: minimum,
		AvailableBytes:        available,
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
