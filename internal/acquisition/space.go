package acquisition

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
)

const downloadSpaceReserve uint64 = 64 * 1024 * 1024

var ErrInsufficientSpace = errors.New("insufficient free space for verified download")

type spaceProbe func(string) (uint64, error)

// InsufficientSpaceError reports the exact destination-filesystem capacity
// decision made before an acquisition request is sent.
type InsufficientSpaceError struct {
	Directory string
	Required  uint64
	Available uint64
}

func (err *InsufficientSpaceError) Error() string {
	return fmt.Sprintf(
		"insufficient free space in %s for verified download: need %d bytes, have %d bytes",
		err.Directory,
		err.Required,
		err.Available,
	)
}

func (err *InsufficientSpaceError) Unwrap() error {
	return ErrInsufficientSpace
}

func preflightDownloadSpace(destination string, imageSize uint64, probe spaceProbe) error {
	directory := filepath.Dir(destination)
	required, err := requiredDownloadBytes(imageSize)
	if err != nil {
		return err
	}
	if probe == nil {
		probe = availableDownloadBytes
	}
	available, err := probe(directory)
	if err != nil {
		return fmt.Errorf("query available download space in %s: %w", directory, err)
	}
	if available < required {
		return &InsufficientSpaceError{
			Directory: directory,
			Required:  required,
			Available: available,
		}
	}
	return nil
}

func requiredDownloadBytes(imageSize uint64) (uint64, error) {
	if imageSize == 0 {
		return 0, fmt.Errorf("download image size must be greater than zero")
	}
	const maxUint64 = ^uint64(0)
	if imageSize > maxUint64-downloadSpaceReserve {
		return 0, fmt.Errorf("download storage requirement overflows: image size %d", imageSize)
	}
	return imageSize + downloadSpaceReserve, nil
}

func availableDownloadBytes(path string) (uint64, error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return 0, err
	}
	if stats.Bsize <= 0 {
		return 0, fmt.Errorf("filesystem reported invalid block size %d", stats.Bsize)
	}
	blockSize := uint64(stats.Bsize)
	const maxUint64 = ^uint64(0)
	if stats.Bavail > maxUint64/blockSize {
		return 0, fmt.Errorf("filesystem available-byte count overflows")
	}
	// Bavail intentionally excludes blocks reserved from unprivileged callers.
	return stats.Bavail * blockSize, nil
}
