//go:build linux

package isocapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const FilesystemCapturePlanSchema = 1

var filesystemCaptureLimitations = []string{
	"The ISO is a filesystem remaster, not a physical-disk image.",
	"Partition tables, hidden sectors, boot records and unallocated space are not captured.",
	"Bootability is not claimed or inferred from successful filesystem capture.",
	"Only the reviewed regular-file and directory subset is supported.",
}

type FilesystemCapturePlan struct {
	Schema              int      `json:"schema"`
	Format              string   `json:"format"`
	Profile             string   `json:"profile"`
	Filesystem          string   `json:"filesystem"`
	VolumeID            string   `json:"volume_id"`
	Provider             string   `json:"provider"`
	SourceDevice        string   `json:"source_device"`
	SourceMount         string   `json:"source_mount"`
	Destination         string   `json:"destination"`
	Files               uint64   `json:"files"`
	Directories         uint64   `json:"directories"`
	SourceBytes         uint64   `json:"source_bytes"`
	RequiredBytes       uint64   `json:"required_bytes"`
	AvailableBytes      uint64   `json:"available_bytes"`
	SourceBindingSHA256 string   `json:"source_binding_sha256"`
	SourceContentSHA256 string   `json:"source_content_sha256"`
	Limitations         []string `json:"limitations"`
}

// InspectFilesystemCapture performs the complete non-privileged plan. The live
// source is inventoried but no bind mount, output file, image or publication is
// created.
func InspectFilesystemCapture(ctx context.Context, sourceMount, outputPath, sourceDevicePath, volumeID string, limits Limits) (FilesystemCapturePlan, error) {
	if ctx == nil {
		return FilesystemCapturePlan{}, errors.New("ISO capture plan context is nil")
	}
	if err := ctx.Err(); err != nil {
		return FilesystemCapturePlan{}, err
	}
	cleanSource := filepath.Clean(sourceMount)
	if sourceMount == "" || !filepath.IsAbs(cleanSource) || cleanSource == string(filepath.Separator) {
		return FilesystemCapturePlan{}, errors.New("ISO capture source must be an absolute non-root mountpoint")
	}
	pathInfo, err := os.Lstat(cleanSource)
	if err != nil {
		return FilesystemCapturePlan{}, fmt.Errorf("inspect ISO capture source mountpoint: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return FilesystemCapturePlan{}, errors.New("ISO capture source mountpoint must be a real directory")
	}
	root, err := os.OpenFile(cleanSource, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return FilesystemCapturePlan{}, fmt.Errorf("open ISO capture source mountpoint: %w", err)
	}
	defer root.Close()
	openInfo, err := root.Stat()
	if err != nil {
		return FilesystemCapturePlan{}, fmt.Errorf("inspect open ISO capture source mountpoint: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		return FilesystemCapturePlan{}, errors.New("ISO capture source mountpoint changed while it was opened")
	}
	inventory, err := Scan(ctx, root, limits)
	if err != nil {
		return FilesystemCapturePlan{}, fmt.Errorf("inventory ISO capture source: %w", err)
	}
	provider, err := BuildProviderPlan(ProfileISO9660JolietUDF, volumeID)
	if err != nil {
		return FilesystemCapturePlan{}, err
	}
	required, err := masteringOutputLimit(inventory.TotalBytes, uint64(len(inventory.Entries)))
	if err != nil {
		return FilesystemCapturePlan{}, err
	}
	destination, err := prepareISODestination(outputPath, sourceDevicePath, required)
	if err != nil {
		return FilesystemCapturePlan{}, err
	}
	defer destination.Directory.Close()
	limitations := append([]string(nil), filesystemCaptureLimitations...)
	return FilesystemCapturePlan{
		Schema:              FilesystemCapturePlanSchema,
		Format:              "iso",
		Profile:             ProfileISO9660JolietUDF,
		Filesystem:          "udf",
		VolumeID:            provider.VolumeID,
		Provider:            provider.Executable,
		SourceDevice:        sourceDevicePath,
		SourceMount:         cleanSource,
		Destination:         destination.Path,
		Files:               inventory.Files,
		Directories:         inventory.Directories,
		SourceBytes:         inventory.TotalBytes,
		RequiredBytes:       required,
		AvailableBytes:      destination.AvailableBytes,
		SourceBindingSHA256: inventory.BindingSHA256,
		SourceContentSHA256: inventory.ContentSHA256,
		Limitations:         limitations,
	}, nil
}
