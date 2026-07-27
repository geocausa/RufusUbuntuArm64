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
	OmittedRootAliases   int     `json:"omitted_root_aliases,omitempty"`
	TotalBytes           uint64  `json:"total_bytes"`
	UEFIBootPath         string  `json:"uefi_boot_path,omitempty"`
}

type manifestBuilder struct {
	ctx      context.Context
	root     string
	opts     Options
	manifest Manifest
	seen     map[string]string
}

func Inspect(ctx context.Context, root string, opts Options) (Manifest, error) {
	if ctx == nil {
		return Manifest{}, errors.New("media inspection context is nil")
	}
	root, err := resolveRoot(root)
	if err != nil {
		return Manifest{}, err
	}
	opts, err = normalizeOptions(opts)
	if err != nil {
		return Manifest{}, err
	}
	builder := manifestBuilder{
		ctx:  ctx,
		root: root,
		opts: opts,
		manifest: Manifest{
			SourceRoot:   root,
			Architecture: opts.Architecture,
		},
		seen: make(map[string]string),
	}
	rootKey, err := canonicalDirectory(root)
	if err != nil {
		return Manifest{}, err
	}
	if err := builder.walkDirectory(root, "", map[string]struct{}{rootKey: {}}); err != nil {
		return Manifest{}, err
	}

	bootPath := uefiBootPath(opts.Architecture)
	if bootPath != "" {
		for _, entry := range builder.manifest.Entries {
			if strings.EqualFold(entry.Path, bootPath) && entry.SHA256 != "" {
				builder.manifest.UEFIBootPath = entry.Path
				break
			}
		}
	}
	if opts.RequireUEFI && builder.manifest.UEFIBootPath == "" {
		return Manifest{}, fmt.Errorf("media tree has no %s fallback UEFI bootloader", bootPath)
	}
	sort.Slice(builder.manifest.Entries, func(i, j int) bool {
		return builder.manifest.Entries[i].Path < builder.manifest.Entries[j].Path
	})
	return builder.manifest, nil
}

func (builder *manifestBuilder) walkDirectory(sourceDirectory, logicalDirectory string, ancestors map[string]struct{}) error {
	entries, err := os.ReadDir(sourceDirectory)
	if err != nil {
		return err
	}
	for _, directoryEntry := range entries {
		if err := builder.ctx.Err(); err != nil {
			return err
		}
		sourcePath := filepath.Join(sourceDirectory, directoryEntry.Name())
		logicalPath := directoryEntry.Name()
		if logicalDirectory != "" {
			logicalPath = filepath.Join(logicalDirectory, directoryEntry.Name())
		}
		if err := builder.inspectPath(sourcePath, logicalPath, ancestors); err != nil {
			return err
		}
	}
	return nil
}

func (builder *manifestBuilder) inspectPath(sourcePath, logicalPath string, ancestors map[string]struct{}) error {
	logicalPath = filepath.Clean(logicalPath)
	if !filepath.IsLocal(logicalPath) || logicalPath == "." {
		return fmt.Errorf("unsafe media path %q", logicalPath)
	}
	if len(builder.manifest.Entries) >= builder.opts.MaxEntries {
		return fmt.Errorf("media tree exceeds the %d-entry safety limit", builder.opts.MaxEntries)
	}
	if builder.opts.RequireFAT32 {
		if err := validateFATPath(logicalPath); err != nil {
			return err
		}
	}

	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	entry := Entry{Path: filepath.ToSlash(logicalPath), Mode: uint32(info.Mode().Perm())}
	if info.Mode()&os.ModeSymlink == 0 {
		if err := builder.registerFATPath(logicalPath); err != nil {
			return err
		}
	}
	switch {
	case info.IsDir():
		builder.manifest.Directories++
		builder.manifest.Entries = append(builder.manifest.Entries, entry)
		return builder.descendDirectory(sourcePath, logicalPath, ancestors, false)
	case info.Mode()&os.ModeSymlink != 0:
		resolved, resolvedInfo, rootAlias, err := resolveMediaSymlink(builder.root, sourcePath)
		if err != nil {
			return fmt.Errorf("inspect symbolic link %s: %w", entry.Path, err)
		}
		if rootAlias {
			// Official Ubuntu media can contain a root-level convenience alias such
			// as "ubuntu -> .". FAT32 cannot represent it and materializing it would
			// recursively duplicate the entire image. It is not boot payload, so omit
			// only this exact, direct-child alias while retaining strict rejection of
			// nested root links and all links outside the mounted media tree.
			builder.manifest.OmittedRootAliases++
			return nil
		}
		if err := builder.registerFATPath(logicalPath); err != nil {
			return err
		}
		entry.Mode = uint32(resolvedInfo.Mode().Perm())
		entry.DereferencedSymlink = true
		builder.manifest.DereferencedSymlinks++
		if resolvedInfo.IsDir() {
			builder.manifest.Directories++
			builder.manifest.Entries = append(builder.manifest.Entries, entry)
			return builder.descendDirectory(resolved, logicalPath, ancestors, true)
		}
		entry.SourcePath = resolved
		entry.Size = uint64(resolvedInfo.Size())
	case info.Mode().IsRegular():
		entry.SourcePath = sourcePath
		entry.Size = uint64(info.Size())
	default:
		return fmt.Errorf("unsupported non-regular media entry %q", entry.Path)
	}

	if builder.opts.RequireFAT32 && entry.Size > fat32MaxFileSize {
		return fmt.Errorf("%s is %d bytes and exceeds the FAT32 single-file limit", entry.Path, entry.Size)
	}
	if entry.Size > builder.opts.MaxBytes-builder.manifest.TotalBytes {
		return fmt.Errorf("media tree exceeds the %d-byte safety limit", builder.opts.MaxBytes)
	}
	digest, err := hashStableFile(builder.ctx, entry.SourcePath, entry.Size)
	if err != nil {
		return fmt.Errorf("hash %s: %w", entry.Path, err)
	}
	entry.SHA256 = hex.EncodeToString(digest[:])
	builder.manifest.TotalBytes += entry.Size
	builder.manifest.Files++
	builder.manifest.Entries = append(builder.manifest.Entries, entry)
	return nil
}

func (builder *manifestBuilder) registerFATPath(logicalPath string) error {
	if !builder.opts.RequireFAT32 {
		return nil
	}
	portablePath := filepath.ToSlash(logicalPath)
	folded := strings.ToLower(portablePath)
	if previous, ok := builder.seen[folded]; ok && previous != portablePath {
		return fmt.Errorf("FAT32 case-insensitive path collision between %q and %q", previous, portablePath)
	}
	builder.seen[folded] = portablePath
	return nil
}

func (builder *manifestBuilder) descendDirectory(sourceDirectory, logicalDirectory string, ancestors map[string]struct{}, symbolic bool) error {
	key, err := canonicalDirectory(sourceDirectory)
	if err != nil {
		return err
	}
	if _, exists := ancestors[key]; exists {
		if symbolic {
			return fmt.Errorf("inspect symbolic link %s: directory link creates a traversal cycle", filepath.ToSlash(logicalDirectory))
		}
		return fmt.Errorf("directory traversal cycle at %s", filepath.ToSlash(logicalDirectory))
	}
	nextAncestors := make(map[string]struct{}, len(ancestors)+1)
	for ancestor := range ancestors {
		nextAncestors[ancestor] = struct{}{}
	}
	nextAncestors[key] = struct{}{}
	return builder.walkDirectory(sourceDirectory, logicalDirectory, nextAncestors)
}

func canonicalDirectory(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(resolved), nil
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

func resolveMediaSymlink(root, path string) (string, os.FileInfo, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, false, err
	}
	resolved = filepath.Clean(resolved)
	root = filepath.Clean(root)
	relative, err := filepath.Rel(root, resolved)
	if err != nil || !filepath.IsLocal(relative) {
		return "", nil, false, errors.New("symbolic link escapes the media root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, false, err
	}
	if relative == "." {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil || filepath.Clean(parent) != root || !info.IsDir() {
			return "", nil, false, errors.New("symbolic link creates an unsafe media-root traversal")
		}
		return resolved, info, true, nil
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return "", nil, false, errors.New("symbolic link target is neither a regular file nor a directory")
	}
	return resolved, info, false, nil
}

type linuxMediaOpenFunc func(string) (*os.File, error)

func openLinuxMediaNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create Linux media source file handle")
	}
	return file, nil
}

func hashStableFile(ctx context.Context, path string, expectedSize uint64) ([sha256.Size]byte, error) {
	return hashStableFileWithOpen(ctx, path, expectedSize, openLinuxMediaNoFollow)
}

func hashStableFileWithOpen(ctx context.Context, path string, expectedSize uint64, open linuxMediaOpenFunc) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	before, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) != expectedSize {
		return result, errors.New("source file identity changed before hashing")
	}
	file, err := open(path)
	if err != nil {
		return result, err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !opened.Mode().IsRegular() || opened.Size() < 0 || uint64(opened.Size()) != expectedSize || !os.SameFile(before, opened) {
		return result, errors.New("source file identity changed while it was being opened")
	}
	hash := sha256.New()
	buffer := make([]byte, copyBufferSize)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += uint64(n)
			if total > expectedSize {
				return result, errors.New("source file grew while it was hashed")
			}
			if _, err := hash.Write(buffer[:n]); err != nil {
				return result, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	after, err := file.Stat()
	if err != nil {
		return result, err
	}
	if total != expectedSize || !sameIdentity(opened, after) {
		return result, errors.New("source file changed while it was hashed")
	}
	if err := file.Close(); err != nil {
		file = nil
		return result, err
	}
	file = nil
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
