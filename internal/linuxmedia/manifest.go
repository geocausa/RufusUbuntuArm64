//go:build linux

// Package linuxmedia plans and copies writable Linux live-media trees.
// It is intentionally internal: it contains bounded source inspection, verified
// copying, and the explicit CLI-only privileged orchestration used by the
// experimental persistence writer.
package linuxmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	defaultMaxEntries = 250000
	defaultMaxBytes   = uint64(16 * 1024 * 1024 * 1024)
	fat32MaxFileSize  = uint64(4*1024*1024*1024 - 1)
	copyBufferSize    = 4 * 1024 * 1024
)

type Options struct {
	Architecture string
	RequireUEFI  bool
	RequireFAT32 bool
	MaxEntries   int
	MaxBytes     uint64
}

type Entry struct {
	Path                string `json:"path"`
	SourcePath          string `json:"-"`
	Size                uint64 `json:"size"`
	Mode                uint32 `json:"mode"`
	SHA256              string `json:"sha256,omitempty"`
	DereferencedSymlink bool   `json:"dereferenced_symlink,omitempty"`
}

type Manifest struct {
	SourceRoot           string  `json:"source_root"`
	Architecture         string  `json:"architecture"`
	Entries              []Entry `json:"entries"`
	Files                int     `json:"files"`
	Directories          int     `json:"directories"`
	DereferencedSymlinks int     `json:"dereferenced_symlinks"`
	TotalBytes           uint64  `json:"total_bytes"`
	UEFIBootPath         string  `json:"uefi_boot_path,omitempty"`
}

func Inspect(ctx context.Context, root string, opts Options) (Manifest, error) {
	root, err := resolveRoot(root)
	if err != nil {
		return Manifest{}, err
	}
	opts, err = normalizeOptions(opts)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{SourceRoot: root, Architecture: opts.Architecture}
	seen := make(map[string]string)
	walkErr := filepath.WalkDir(root, func(path string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.Clean(relative)
		if !filepath.IsLocal(relative) {
			return fmt.Errorf("unsafe media path %q", relative)
		}
		if len(manifest.Entries) >= opts.MaxEntries {
			return fmt.Errorf("media tree exceeds the %d-entry safety limit", opts.MaxEntries)
		}
		if opts.RequireFAT32 {
			if err := validateFATPath(relative); err != nil {
				return err
			}
			folded := strings.ToLower(filepath.ToSlash(relative))
			if previous, ok := seen[folded]; ok && previous != filepath.ToSlash(relative) {
				return fmt.Errorf("FAT32 case-insensitive path collision between %q and %q", previous, filepath.ToSlash(relative))
			}
			seen[folded] = filepath.ToSlash(relative)
		}

		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		entry := Entry{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			manifest.Directories++
			manifest.Entries = append(manifest.Entries, entry)
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			resolved, resolvedInfo, err := resolveFileSymlink(root, path)
			if err != nil {
				return fmt.Errorf("inspect symbolic link %s: %w", entry.Path, err)
			}
			entry.SourcePath = resolved
			entry.DereferencedSymlink = true
			entry.Size = uint64(resolvedInfo.Size())
			entry.Mode = uint32(resolvedInfo.Mode().Perm())
			manifest.DereferencedSymlinks++
		case info.Mode().IsRegular():
			entry.SourcePath = path
			entry.Size = uint64(info.Size())
		default:
			return fmt.Errorf("unsupported non-regular media entry %q", entry.Path)
		}
		if opts.RequireFAT32 && entry.Size > fat32MaxFileSize {
			return fmt.Errorf("%s is %d bytes and exceeds the FAT32 single-file limit", entry.Path, entry.Size)
		}
		if entry.Size > opts.MaxBytes-manifest.TotalBytes {
			return fmt.Errorf("media tree exceeds the %d-byte safety limit", opts.MaxBytes)
		}
		digest, err := hashStableFile(ctx, entry.SourcePath, entry.Size)
		if err != nil {
			return fmt.Errorf("hash %s: %w", entry.Path, err)
		}
		entry.SHA256 = hex.EncodeToString(digest[:])
		manifest.TotalBytes += entry.Size
		manifest.Files++
		manifest.Entries = append(manifest.Entries, entry)
		return nil
	})
	if walkErr != nil {
		return Manifest{}, walkErr
	}
	bootPath := uefiBootPath(opts.Architecture)
	if bootPath != "" {
		for _, entry := range manifest.Entries {
			if strings.EqualFold(entry.Path, bootPath) && entry.SHA256 != "" {
				manifest.UEFIBootPath = entry.Path
				break
			}
		}
	}
	if opts.RequireUEFI && manifest.UEFIBootPath == "" {
		return Manifest{}, fmt.Errorf("media tree has no %s fallback UEFI bootloader", bootPath)
	}
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	return manifest, nil
}

func normalizeOptions(opts Options) (Options, error) {
	opts.Architecture = strings.ToLower(strings.TrimSpace(opts.Architecture))
	if opts.Architecture == "" {
		opts.Architecture = "arm64"
	}
	switch opts.Architecture {
	case "arm64", "amd64", "386":
	default:
		return Options{}, fmt.Errorf("unsupported Linux media architecture %q", opts.Architecture)
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	return opts, nil
}

func resolveRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("media root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve media root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("media root is not a directory")
	}
	return resolved, nil
}

func resolveFileSymlink(root, path string) (string, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return "", nil, errors.New("symbolic link escapes the media root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, errors.New("only symbolic links to regular files are supported")
	}
	return resolved, info, nil
}

func hashStableFile(ctx context.Context, path string, expectedSize uint64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	before, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	if !before.Mode().IsRegular() || uint64(before.Size()) != expectedSize {
		return result, errors.New("source file identity changed before hashing")
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	buffer := make([]byte, copyBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			file.Close()
			return result, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			if _, err := hash.Write(buffer[:n]); err != nil {
				file.Close()
				return result, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			file.Close()
			return result, readErr
		}
	}
	if err := file.Close(); err != nil {
		return result, err
	}
	after, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	if !sameIdentity(before, after) {
		return result, errors.New("source file changed while it was hashed")
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func sameIdentity(left, right os.FileInfo) bool {
	if left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) || left.Mode() != right.Mode() {
		return false
	}
	ls, lok := left.Sys().(*syscall.Stat_t)
	rs, rok := right.Sys().(*syscall.Stat_t)
	return !lok || !rok || (ls.Dev == rs.Dev && ls.Ino == rs.Ino)
}

func uefiBootPath(architecture string) string {
	switch architecture {
	case "arm64":
		return "efi/boot/bootaa64.efi"
	case "amd64":
		return "efi/boot/bootx64.efi"
	case "386":
		return "efi/boot/bootia32.efi"
	default:
		return ""
	}
}

func validateFATPath(relative string) error {
	if !utf8.ValidString(relative) {
		return fmt.Errorf("media path %q is not valid UTF-8", relative)
	}
	if len(filepath.ToSlash(relative)) > 240 {
		return fmt.Errorf("media path %q exceeds the conservative FAT32 path limit", relative)
	}
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("unsafe media path component in %q", relative)
		}
		if len(component) > 255 {
			return fmt.Errorf("media path component %q is too long for FAT32", component)
		}
		if strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") {
			return fmt.Errorf("media path component %q has a FAT32-incompatible suffix", component)
		}
		for _, r := range component {
			if r < 0x20 || strings.ContainsRune(`<>:"\\|?*`, r) {
				return fmt.Errorf("media path component %q contains a FAT32-incompatible character", component)
			}
		}
		base := strings.ToUpper(component)
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if isDOSReserved(base) {
			return fmt.Errorf("media path component %q uses a reserved DOS name", component)
		}
	}
	return nil
}

func isDOSReserved(base string) bool {
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}
