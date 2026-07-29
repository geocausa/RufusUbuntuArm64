//go:build linux

package linuxmedia

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ExtractedFilesystem is a reviewed ISO Image mode data-filesystem choice.
type ExtractedFilesystem string

const (
	ExtractedFilesystemAutomatic ExtractedFilesystem = "auto"
	ExtractedFilesystemFAT32     ExtractedFilesystem = "fat32"
	ExtractedFilesystemNTFS      ExtractedFilesystem = "ntfs"
)

// ExtractedFilesystemSelection records the requested and resolved choice. A
// non-empty FAT32Refusal explains why Automatic selected NTFS.
type ExtractedFilesystemSelection struct {
	Requested    ExtractedFilesystem `json:"requested"`
	Selected     ExtractedFilesystem `json:"selected"`
	FAT32Refusal string              `json:"fat32_refusal,omitempty"`
}

// ResolveExtractedFilesystem applies Rufus-style Automatic/FAT32/NTFS policy to
// an already identity-bound and hashed Linux media manifest.
func ResolveExtractedFilesystem(requested string, manifest Manifest) (ExtractedFilesystemSelection, error) {
	choice, err := normalizeExtractedFilesystem(requested)
	if err != nil {
		return ExtractedFilesystemSelection{}, err
	}
	if len(manifest.Entries) == 0 || manifest.Files == 0 {
		return ExtractedFilesystemSelection{}, errors.New("linux media manifest is empty")
	}
	if strings.TrimSpace(manifest.UEFIBootPath) == "" {
		return ExtractedFilesystemSelection{}, errors.New("linux ISO Image mode requires a native fallback UEFI loader")
	}

	fatErr := validateExtractedManifestFAT32(manifest)
	switch choice {
	case ExtractedFilesystemFAT32:
		if fatErr != nil {
			return ExtractedFilesystemSelection{}, fmt.Errorf("FAT32 is incompatible with this Linux media tree: %w", fatErr)
		}
		return ExtractedFilesystemSelection{Requested: choice, Selected: choice}, nil
	case ExtractedFilesystemNTFS:
		if err := validateExtractedManifestNTFS(manifest); err != nil {
			return ExtractedFilesystemSelection{}, fmt.Errorf("NTFS is incompatible with this Linux media tree: %w", err)
		}
		return ExtractedFilesystemSelection{Requested: choice, Selected: choice}, nil
	case ExtractedFilesystemAutomatic:
		if fatErr == nil {
			return ExtractedFilesystemSelection{Requested: choice, Selected: ExtractedFilesystemFAT32}, nil
		}
		if err := validateExtractedManifestNTFS(manifest); err != nil {
			return ExtractedFilesystemSelection{}, fmt.Errorf("media tree is incompatible with both FAT32 (%v) and NTFS (%w)", fatErr, err)
		}
		return ExtractedFilesystemSelection{
			Requested:    choice,
			Selected:     ExtractedFilesystemNTFS,
			FAT32Refusal: fatErr.Error(),
		}, nil
	default:
		return ExtractedFilesystemSelection{}, fmt.Errorf("unsupported Linux ISO Image mode filesystem %q", choice)
	}
}

func normalizeExtractedFilesystem(value string) (ExtractedFilesystem, error) {
	normalized := ExtractedFilesystem(strings.ToLower(strings.TrimSpace(value)))
	if normalized == "" {
		normalized = ExtractedFilesystemAutomatic
	}
	switch normalized {
	case ExtractedFilesystemAutomatic, ExtractedFilesystemFAT32, ExtractedFilesystemNTFS:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported Linux ISO Image mode filesystem %q; use auto, fat32, or ntfs", value)
	}
}

func validateExtractedManifestFAT32(manifest Manifest) error {
	seen := make(map[string]string, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		path := filepath.ToSlash(strings.TrimSpace(entry.Path))
		if err := validateFATPath(path); err != nil {
			return err
		}
		key := strings.ToLower(path)
		if previous, exists := seen[key]; exists && previous != path {
			return fmt.Errorf("FAT32 case-insensitive path collision between %q and %q", previous, path)
		}
		seen[key] = path
		if entry.SHA256 != "" && entry.Size > fat32MaxFileSize {
			return fmt.Errorf("%s is %d bytes and exceeds the FAT32 single-file limit", path, entry.Size)
		}
	}
	return nil
}

func validateExtractedManifestNTFS(manifest Manifest) error {
	seen := make(map[string]string, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		path := filepath.ToSlash(strings.TrimSpace(entry.Path))
		if err := validateNTFSPath(path); err != nil {
			return err
		}
		key := strings.ToLower(path)
		if previous, exists := seen[key]; exists && previous != path {
			return fmt.Errorf("NTFS case-insensitive path collision between %q and %q", previous, path)
		}
		seen[key] = path
	}
	return nil
}

func validateNTFSPath(relative string) error {
	if !utf8.ValidString(relative) {
		return fmt.Errorf("media path %q is not valid UTF-8", relative)
	}
	if len(utf16.Encode([]rune(relative))) > 32767 {
		return fmt.Errorf("media path %q exceeds the NTFS long-path boundary", relative)
	}
	components := strings.Split(filepath.ToSlash(relative), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("unsafe media path component in %q", relative)
		}
		if len(utf16.Encode([]rune(component))) > 255 {
			return fmt.Errorf("media path component %q is too long for NTFS", component)
		}
		if strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") {
			return fmt.Errorf("media path component %q has an NTFS-incompatible suffix", component)
		}
		for _, r := range component {
			if r < 0x20 || strings.ContainsRune(`<>:"\\|?*`, r) {
				return fmt.Errorf("media path component %q contains an NTFS-incompatible character", component)
			}
		}
		base := strings.ToUpper(component)
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if isDOSReserved(base) || isNTFSMetadataName(base) {
			return fmt.Errorf("media path component %q uses a reserved NTFS name", component)
		}
	}
	return nil
}

func isNTFSMetadataName(base string) bool {
	switch strings.ToUpper(base) {
	case "$MFT", "$MFTMIRR", "$LOGFILE", "$VOLUME", "$ATTRDEF", "$BITMAP", "$BOOT", "$BADCLUS", "$SECURE", "$UPCASE", "$EXTEND":
		return true
	default:
		return false
	}
}
