package drivebackup

import (
	"errors"
	"fmt"
	"strings"
)

// Format is an explicitly supported drive-backup output format. Raw remains the
// default; VHD and VHDX are always dynamic sparse containers.
type Format string

const (
	FormatRaw  Format = "raw"
	FormatVHD  Format = "vhd"
	FormatVHDX Format = "vhdx"
)

func ParseFormat(value string) (Format, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return FormatRaw, nil
	}
	format := Format(normalized)
	if !format.Valid() {
		return "", fmt.Errorf("backup format must be raw, vhd, or vhdx, not %q", value)
	}
	return format, nil
}

func (format Format) Valid() bool {
	switch format {
	case FormatRaw, FormatVHD, FormatVHDX:
		return true
	default:
		return false
	}
}

func (format Format) Container() bool {
	return format == FormatVHD || format == FormatVHDX
}

func (format Format) QEMUFormat() (string, error) {
	switch format {
	case FormatVHD:
		return "vpc", nil
	case FormatVHDX:
		return "vhdx", nil
	case FormatRaw:
		return "", errors.New("raw backup does not use qemu-img")
	default:
		return "", fmt.Errorf("unsupported backup format %q", format)
	}
}

// QEMUOptions returns the complete fixed option set accepted for container
// creation. Callers cannot add backing files, compression, encryption, salvage,
// preallocation, or other converter-controlled policy.
func (format Format) QEMUOptions() (string, error) {
	switch format {
	case FormatVHD:
		// force_size preserves the exact source capacity instead of CHS rounding.
		return "subformat=dynamic,force_size=on", nil
	case FormatVHDX:
		// block_state_zero=on is required for deterministic zero semantics when
		// converting to a dynamic VHDX.
		return "subformat=dynamic,block_state_zero=on", nil
	case FormatRaw:
		return "", errors.New("raw backup does not use qemu-img")
	default:
		return "", fmt.Errorf("unsupported backup format %q", format)
	}
}

func (format Format) Extension() string {
	switch format {
	case FormatVHD:
		return ".vhd"
	case FormatVHDX:
		return ".vhdx"
	default:
		return ".img"
	}
}
