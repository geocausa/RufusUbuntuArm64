//go:build linux

package runtimeintegrity

import (
	"bufio"
	"context"
	"crypto/md5" // #nosec G501 -- required for compatibility with upstream uefi-md5sum.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const hashBufferSize = 1024 * 1024

type Progress struct {
	Stage      string `json:"stage"`
	Path       string `json:"path,omitempty"`
	FilesDone  int    `json:"files_done"`
	FilesTotal int    `json:"files_total"`
	BytesDone  uint64 `json:"bytes_done"`
	BytesTotal uint64 `json:"bytes_total"`
}

type Options struct {
	MaxFiles int
	Progress func(Progress)
}

type VerificationFile struct {
	Path        string `json:"path"`
	ExpectedMD5 string `json:"expected_md5,omitempty"`
	ActualMD5   string `json:"actual_md5,omitempty"`
	Size        uint64 `json:"size,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

type VerificationResult struct {
	Root               string             `json:"root"`
	ManifestPath       string             `json:"manifest_path"`
	DeclaredTotalBytes uint64             `json:"declared_total_bytes"`
	ActualTotalBytes   uint64             `json:"actual_total_bytes"`
	Files              []VerificationFile `json:"files"`
	Unexpected         []string           `json:"unexpected,omitempty"`
	Valid              bool               `json:"valid"`
	Errors             []string           `json:"errors,omitempty"`
}

type treeHook func(stage, relative string)

type fileIdentity struct {
	device     uint64
	inode      uint64
	mode       uint32
	size       int64
	modifiedNS int64
	changedNS  int64
}

type treeEntry struct {
	relative string
	identity fileIdentity
}

type hashedEntry struct {
	Entry
	identity fileIdentity
}

func Generate(ctx context.Context, root string, opts Options) (Manifest, error) {
	return generate(ctx, root, opts, nil)
}

func generate(ctx context.Context, root string, opts Options, hook treeHook) (Manifest, error) {
	resolved, rootFile, rootIdentity, entries, total, err := enumerateTree(ctx, root, opts, hook, false)
	if err != nil {
		return Manifest{}, err
	}
	defer rootFile.Close()
	_ = resolved
	hashed, err := hashEntries(ctx, rootFile, rootIdentity, entries, total, opts, hook)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{TotalBytes: total, Entries: make([]Entry, 0, len(hashed))}
	for _, entry := range hashed {
		manifest.Entries = append(manifest.Entries, entry.Entry)
	}
	if _, err := manifest.MarshalText(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Verify reads the exact root md5sum.txt through the retained root descriptor,
// snapshots every other regular file, and reports changed, missing, and
// unexpected paths.
func Verify(ctx context.Context, root string, opts Options) (VerificationResult, error) {
	return verify(ctx, root, opts, nil)
}

func verify(ctx context.Context, root string, opts Options, hook treeHook) (VerificationResult, error) {
	resolved, rootFile, rootIdentity, entries, total, err := enumerateTree(ctx, root, opts, hook, true)
	if err != nil {
		return VerificationResult{}, err
	}
	defer rootFile.Close()
	manifestData, err := readManifest(rootFile)
	if err != nil {
		return VerificationResult{}, err
	}
	manifest, err := Parse(manifestData)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("parse %s: %w", ManifestName, err)
	}
	hashed, err := hashEntries(ctx, rootFile, rootIdentity, entries, total, opts, hook)
	if err != nil {
		return VerificationResult{}, err
	}
	actual := make(map[string]hashedEntry, len(hashed))
	for _, entry := range hashed {
		actual[strings.ToLower(entry.Path)] = entry
	}
	result := VerificationResult{
		Root:               resolved,
		ManifestPath:       filepath.Join(resolved, ManifestName),
		DeclaredTotalBytes: manifest.TotalBytes,
		ActualTotalBytes:   total,
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, expected := range manifest.Entries {
		key := strings.ToLower(expected.Path)
		seen[key] = struct{}{}
		fileResult := VerificationFile{Path: expected.Path, ExpectedMD5: expected.MD5, Status: "missing"}
		current, exists := actual[key]
		if !exists {
			fileResult.Error = "file is missing"
			result.Errors = append(result.Errors, expected.Path+": file is missing")
			result.Files = append(result.Files, fileResult)
			continue
		}
		fileResult.ActualMD5 = current.MD5
		fileResult.Size = current.Size
		if current.MD5 != expected.MD5 {
			fileResult.Status = "changed"
			fileResult.Error = "MD5 digest does not match"
			result.Errors = append(result.Errors, expected.Path+": MD5 digest does not match")
		} else {
			fileResult.Status = "ok"
		}
		result.Files = append(result.Files, fileResult)
	}
	for _, current := range hashed {
		if _, exists := seen[strings.ToLower(current.Path)]; exists {
			continue
		}
		result.Unexpected = append(result.Unexpected, current.Path)
		result.Errors = append(result.Errors, current.Path+": unexpected file is not covered by the manifest")
	}
	if manifest.TotalBytes != total {
		result.Errors = append(result.Errors, fmt.Sprintf("md5sum_totalbytes is 0x%x but the covered media tree totals 0x%x", manifest.TotalBytes, total))
	}
	result.Valid = len(result.Errors) == 0
	return result, nil
}

func enumerateTree(ctx context.Context, root string, opts Options, hook treeHook, requireManifest bool) (string, *os.File, fileIdentity, []treeEntry, uint64, error) {
	if ctx == nil {
		return "", nil, fileIdentity{}, nil, 0, errors.New("runtime integrity context is nil")
	}
	if strings.TrimSpace(root) == "" {
		return "", nil, fileIdentity{}, nil, 0, errors.New("media root is required")
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaximumFiles
	}
	if maxFiles > MaximumManifestLines {
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("file limit %d exceeds the %d-file safety maximum", maxFiles, MaximumManifestLines)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, fileIdentity{}, nil, 0, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("resolve media root: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("stat media root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fileIdentity{}, nil, 0, errors.New("media root is not a real directory")
	}
	expected, err := identityFromInfo(info)
	if err != nil {
		return "", nil, fileIdentity{}, nil, 0, err
	}
	if hook != nil {
		hook("root-before-open", "")
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("open media root: %w", err)
	}
	rootFile := os.NewFile(uintptr(fd), resolved)
	if rootFile == nil {
		_ = syscall.Close(fd)
		return "", nil, fileIdentity{}, nil, 0, errors.New("create media root descriptor")
	}
	actual, err := identityFromOpenFile(rootFile)
	if err != nil {
		rootFile.Close()
		return "", nil, fileIdentity{}, nil, 0, err
	}
	if !sameKernelObject(expected, actual) {
		rootFile.Close()
		return "", nil, fileIdentity{}, nil, 0, errors.New("media root changed during validation")
	}
	var entries []treeEntry
	var total uint64
	manifestCount := 0
	if err := enumerateDirectory(ctx, rootFile, "", maxFiles, hook, &entries, &total, &manifestCount); err != nil {
		rootFile.Close()
		return "", nil, fileIdentity{}, nil, 0, err
	}
	if requireManifest && manifestCount != 1 {
		rootFile.Close()
		if manifestCount == 0 {
			return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("root %s is missing", ManifestName)
		}
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("root contains multiple case-equivalent %s files", ManifestName)
	}
	if !requireManifest && manifestCount > 1 {
		rootFile.Close()
		return "", nil, fileIdentity{}, nil, 0, fmt.Errorf("root contains multiple case-equivalent %s files", ManifestName)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relative < entries[j].relative })
	return resolved, rootFile, actual, entries, total, nil
}

func enumerateDirectory(ctx context.Context, directory *os.File, prefix string, maxFiles int, hook treeHook, entries *[]treeEntry, total *uint64, manifestCount *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	items, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read directory %q: %w", prefix, err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := item.Name()
		if err := validateEntryName(name); err != nil {
			return fmt.Errorf("directory %q: %w", prefix, err)
		}
		relative := filepath.ToSlash(filepath.Join(prefix, name))
		if len("./"+relative) > MaximumPathBytes {
			return fmt.Errorf("media path %q exceeds the %d-byte limit", relative, MaximumPathBytes)
		}
		info, err := os.Lstat(filepath.Join(directory.Name(), name))
		if err != nil {
			return fmt.Errorf("stat media entry %s: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link %s is not supported by runtime integrity manifests", relative)
		}
		if info.IsDir() {
			if hook != nil {
				hook("entry-before-open", relative)
			}
			child, err := openEntry(directory, name, info, true)
			if err != nil {
				return fmt.Errorf("open directory %s: %w", relative, err)
			}
			err = enumerateDirectory(ctx, child, relative, maxFiles, hook, entries, total, manifestCount)
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular media entry %s is not supported", relative)
		}
		if prefix == "" && strings.EqualFold(name, ManifestName) {
			*manifestCount++
			if name != ManifestName {
				return fmt.Errorf("root manifest name %q must use exact lowercase spelling %q", name, ManifestName)
			}
			continue
		}
		if len(*entries) >= maxFiles {
			return fmt.Errorf("media tree exceeds the %d-file safety limit", maxFiles)
		}
		identity, err := identityFromInfo(info)
		if err != nil {
			return err
		}
		if identity.size < 0 {
			return fmt.Errorf("media entry %s has a negative size", relative)
		}
		size := uint64(identity.size)
		if ^uint64(0)-*total < size {
			return errors.New("media total byte count overflows uint64")
		}
		*total += size
		*entries = append(*entries, treeEntry{relative: relative, identity: identity})
	}
	return nil
}

func hashEntries(ctx context.Context, root *os.File, rootIdentity fileIdentity, entries []treeEntry, total uint64, opts Options, hook treeHook) ([]hashedEntry, error) {
	result := make([]hashedEntry, 0, len(entries))
	var bytesDone uint64
	for index, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if hook != nil {
			hook("file-before-open", entry.relative)
		}
		file, err := openRelativeRegular(root, entry.relative, entry.identity)
		if err != nil {
			return nil, fmt.Errorf("open media file %s: %w", entry.relative, err)
		}
		digest, size, readErr := hashStableFile(ctx, file, entry.identity, func(delta uint64) {
			bytesDone += delta
			if opts.Progress != nil {
				opts.Progress(Progress{Stage: "hash", Path: "./" + entry.relative, FilesDone: index, FilesTotal: len(entries), BytesDone: bytesDone, BytesTotal: total})
			}
		})
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("hash media file %s: %w", entry.relative, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close media file %s: %w", entry.relative, closeErr)
		}
		result = append(result, hashedEntry{Entry: Entry{Path: "./" + entry.relative, MD5: digest, Size: size}, identity: entry.identity})
		if opts.Progress != nil {
			opts.Progress(Progress{Stage: "hash", Path: "./" + entry.relative, FilesDone: index + 1, FilesTotal: len(entries), BytesDone: bytesDone, BytesTotal: total})
		}
	}
	currentRoot, err := identityFromOpenFile(root)
	if err != nil {
		return nil, err
	}
	if !sameStableObject(rootIdentity, currentRoot) {
		return nil, errors.New("media root changed while files were being hashed")
	}
	return result, nil
}

func openRelativeRegular(root *os.File, relative string, expected fileIdentity) (*os.File, error) {
	parts := strings.Split(relative, "/")
	if len(parts) == 0 {
		return nil, errors.New("empty relative path")
	}
	fd, err := syscall.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), root.Name())
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("duplicate root descriptor")
	}
	for index, part := range parts {
		last := index == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if !last {
			flags |= syscall.O_DIRECTORY
		}
		childFD, openErr := syscall.Openat(int(current.Fd()), part, flags, 0)
		current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = os.NewFile(uintptr(childFD), filepath.Join(root.Name(), filepath.FromSlash(strings.Join(parts[:index+1], "/"))))
		if current == nil {
			_ = syscall.Close(childFD)
			return nil, errors.New("create descriptor for media path")
		}
		identity, statErr := identityFromOpenFile(current)
		if statErr != nil {
			current.Close()
			return nil, statErr
		}
		if !last && identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
			current.Close()
			return nil, errors.New("path component is no longer a directory")
		}
		if last {
			if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
				current.Close()
				return nil, errors.New("path is no longer a regular file")
			}
			if !sameStableObject(expected, identity) {
				current.Close()
				return nil, errors.New("file changed between enumeration and hashing")
			}
		}
	}
	return current, nil
}

func openEntry(parent *os.File, name string, expectedInfo os.FileInfo, directory bool) (*os.File, error) {
	expected, err := identityFromInfo(expectedInfo)
	if err != nil {
		return nil, err
	}
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create entry descriptor")
	}
	actual, err := identityFromOpenFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	if !sameKernelObject(expected, actual) {
		file.Close()
		return nil, errors.New("entry changed during traversal")
	}
	return file, nil
}

func readManifest(root *os.File) ([]byte, error) {
	fd, err := syscall.Openat(int(root.Fd()), ManifestName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ManifestName, err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root.Name(), ManifestName))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create manifest descriptor")
	}
	defer file.Close()
	before, err := identityFromOpenFile(file)
	if err != nil {
		return nil, err
	}
	if before.mode&syscall.S_IFMT != syscall.S_IFREG || before.size <= 0 || before.size > MaximumManifestSize {
		return nil, fmt.Errorf("%s must be a non-empty regular file no larger than %d bytes", ManifestName, MaximumManifestSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumManifestSize+1))
	if err != nil {
		return nil, err
	}
	after, err := identityFromOpenFile(file)
	if err != nil {
		return nil, err
	}
	if !sameStableObject(before, after) || int64(len(data)) != before.size {
		return nil, fmt.Errorf("%s changed while it was being read", ManifestName)
	}
	return data, nil
}

func hashStableFile(ctx context.Context, file *os.File, expected fileIdentity, progress func(uint64)) (string, uint64, error) {
	before, err := identityFromOpenFile(file)
	if err != nil {
		return "", 0, err
	}
	if !sameStableObject(expected, before) {
		return "", 0, errors.New("file identity changed before hashing")
	}
	hash := md5.New() // #nosec G401 -- required for uefi-md5sum interoperability.
	reader := bufio.NewReaderSize(file, hashBufferSize)
	buffer := make([]byte, hashBufferSize)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		count, readErr := reader.Read(buffer)
		if count > 0 {
			if _, err := hash.Write(buffer[:count]); err != nil {
				return "", 0, err
			}
			total += uint64(count)
			if progress != nil {
				progress(uint64(count))
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	after, err := identityFromOpenFile(file)
	if err != nil {
		return "", 0, err
	}
	if !sameStableObject(before, after) || total != uint64(before.size) {
		return "", 0, errors.New("file changed while it was being hashed")
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}

func validateEntryName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\\') {
		return fmt.Errorf("unsafe or ambiguous media entry name %q", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("media entry name %q contains a control character", name)
		}
	}
	return nil
}

func identityFromInfo(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("path has unsupported filesystem metadata")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino, mode: stat.Mode, size: stat.Size, modifiedNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec, changedNS: stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec}, nil
}

func identityFromOpenFile(file *os.File) (fileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, err
	}
	return identityFromInfo(info)
}

func sameKernelObject(left, right fileIdentity) bool {
	return left.device == right.device && left.inode == right.inode && left.mode&syscall.S_IFMT == right.mode&syscall.S_IFMT
}

func sameStableObject(left, right fileIdentity) bool {
	return sameKernelObject(left, right) && left.size == right.size && left.modifiedNS == right.modifiedNS && left.changedNS == right.changedNS
}
