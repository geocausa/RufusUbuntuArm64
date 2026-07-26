package drivebackup

import (
	"fmt"
	"strings"
)

// ImageFormat identifies the requested drive-backup container. Raw remains the
// default; VHD and VHDX are sparse dynamic export formats implemented through
// the descriptor-bound QEMU adapter on Linux.
type ImageFormat string

const (
	ImageFormatRaw  ImageFormat = "raw"
	ImageFormatVHD  ImageFormat = "vhd"
	ImageFormatVHDX ImageFormat = "vhdx"
)

func ParseImageFormat(value string) (ImageFormat, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch ImageFormat(value) {
	case ImageFormatRaw, ImageFormatVHD, ImageFormatVHDX:
		return ImageFormat(value), nil
	default:
		return "", fmt.Errorf("unsupported drive-backup format %q; choose raw, vhd, or vhdx", value)
	}
}

func (format ImageFormat) Sparse() bool {
	return format == ImageFormatVHD || format == ImageFormatVHDX
}

func (format ImageFormat) qemuName() (string, error) {
	switch format {
	case ImageFormatVHD:
		return "vpc", nil
	case ImageFormatVHDX:
		return "vhdx", nil
	default:
		return "", fmt.Errorf("drive-backup format %q is not a sparse QEMU output format", format)
	}
}
