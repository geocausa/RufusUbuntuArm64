//go:build linux

package linuxmedia

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// MergeManifestOverlay combines one primary ISO tree with a read-only boot
// image overlay. Exact duplicate files are accepted only when their complete
// content evidence agrees. Every other exact or case-folded collision fails.
func MergeManifestOverlay(base, overlay Manifest, opts Options) (Manifest, error) {
	opts, err := normalizeOptions(opts)
	if err != nil {
		return Manifest{}, err
	}
	if len(base.Entries) == 0 || len(overlay.Entries) == 0 {
		return Manifest{}, errors.New("both base and overlay manifests are required")
	}
	if base.Architecture != overlay.Architecture || base.Architecture != opts.Architecture {
		return Manifest{}, errors.New("base and overlay architecture evidence does not agree")
	}
	roots := manifestSourceRoots(Manifest{SourceRoots: append(manifestSourceRoots(base), manifestSourceRoots(overlay)...)})
	if len(roots) < 2 {
		return Manifest{}, errors.New("overlay merge requires distinct approved source roots")
	}
	merged := Manifest{
		SourceRoot:         base.SourceRoot,
		SourceRoots:        roots,
		Architecture:       opts.Architecture,
		OmittedRootAliases: base.OmittedRootAliases + overlay.OmittedRootAliases,
		UEFIBootPath:       base.UEFIBootPath,
	}
	entries := make(map[string]Entry, len(base.Entries)+len(overlay.Entries))
	folded := make(map[string]string, len(base.Entries)+len(overlay.Entries))
	add := func(entry Entry, source string) error {
		path := filepath.ToSlash(strings.TrimSpace(entry.Path))
		if !filepath.IsLocal(filepath.FromSlash(path)) || path == "." {
			return fmt.Errorf("unsafe %s manifest path %q", source, entry.Path)
		}
		key := strings.ToLower(path)
		if previous, exists := folded[key]; exists && previous != path {
			return fmt.Errorf("case-insensitive path collision between %q and %q across ISO and El Torito trees", previous, path)
		}
		folded[key] = path
		if existing, exists := entries[path]; exists {
			bothDirectories := existing.SHA256 == "" && entry.SHA256 == ""
			identicalFiles := existing.SHA256 != "" && entry.SHA256 != "" &&
				existing.Size == entry.Size && existing.SHA256 == entry.SHA256
			if bothDirectories || identicalFiles {
				return nil
			}
			return fmt.Errorf("el Torito overlay conflicts with ISO path %q", path)
		}
		entries[path] = entry
		return nil
	}
	for _, entry := range base.Entries {
		if err := add(entry, "ISO"); err != nil {
			return Manifest{}, err
		}
	}
	for _, entry := range overlay.Entries {
		if err := add(entry, "El Torito"); err != nil {
			return Manifest{}, err
		}
	}
	merged.Entries = make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if len(merged.Entries) >= opts.MaxEntries {
			return Manifest{}, fmt.Errorf("combined media tree exceeds the %d-entry safety limit", opts.MaxEntries)
		}
		if entry.SHA256 == "" {
			merged.Directories++
		} else {
			if entry.Size > opts.MaxBytes-merged.TotalBytes {
				return Manifest{}, fmt.Errorf("combined media tree exceeds the %d-byte safety limit", opts.MaxBytes)
			}
			merged.Files++
			merged.TotalBytes += entry.Size
			if entry.DereferencedSymlink {
				merged.DereferencedSymlinks++
			}
		}
		merged.Entries = append(merged.Entries, entry)
	}
	sort.Slice(merged.Entries, func(i, j int) bool { return merged.Entries[i].Path < merged.Entries[j].Path })
	if merged.UEFIBootPath == "" {
		merged.UEFIBootPath = overlay.UEFIBootPath
	}
	if opts.RequireUEFI && merged.UEFIBootPath == "" {
		return Manifest{}, fmt.Errorf("combined media tree has no %s fallback UEFI bootloader", uefiBootPath(opts.Architecture))
	}
	if opts.RequireFAT32 {
		if err := validateExtractedManifestFAT32(merged); err != nil {
			return Manifest{}, err
		}
	}
	return merged, nil
}
