//go:build linux

package secureboot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ScanEFIDirectoryContext checks every descriptor-bound EFI executable and
// root bootmgr candidate against one DBX snapshot. Hash and embedded-certificate
// facts are derived from the same stable bytes.
func ScanEFIDirectoryContext(ctx context.Context, root string, db *Database, maxFiles int) ([]CheckResult, error) {
	return scanEFIDirectoryContextWithHook(ctx, root, db, maxFiles, nil)
}

func scanEFIDirectoryContextWithHook(ctx context.Context, root string, db *Database, maxFiles int, hook uefiTraversalHook) ([]CheckResult, error) {
	if ctx == nil {
		return nil, errors.New("DBX scan context is required")
	}
	if db == nil {
		return nil, errors.New("secure boot revocation database is required")
	}
	if maxFiles <= 0 {
		maxFiles = 512
	}
	limits := newUEFITraversalLimits(maxFiles)
	if err := limits.validate(); err != nil {
		return nil, err
	}
	resolved, rootFile, err := openDBXScanRoot(root, hook)
	if err != nil {
		return nil, err
	}
	defer rootFile.Close()

	files := make([]uefiMediaFile, 0)
	if err := walkDBXDirectory(ctx, rootFile, "", 0, limits, hook, &files); err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].relative < files[j].relative })
	results := make([]CheckResult, 0, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		results = append(results, checkPEData(file.relative, file.data, db))
	}
	_ = resolved // retained for diagnostics while result paths stay relative
	return results, nil
}

func openDBXScanRoot(root string, hook uefiTraversalHook) (string, *os.File, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil, errors.New("DBX scan root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, fmt.Errorf("make DBX scan root absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, fmt.Errorf("resolve DBX scan root: %w", err)
	}
	expectedInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("stat DBX scan root: %w", err)
	}
	if !expectedInfo.IsDir() {
		return "", nil, errors.New("DBX scan root is not a directory")
	}
	expected, err := uefiIdentityFromInfo(expectedInfo)
	if err != nil {
		return "", nil, fmt.Errorf("identify DBX scan root: %w", err)
	}
	if hook != nil {
		hook("root-before-open", "")
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, fmt.Errorf("open DBX scan root without following links: %w", err)
	}
	rootFile := os.NewFile(uintptr(fd), resolved)
	if rootFile == nil {
		_ = syscall.Close(fd)
		return "", nil, errors.New("create DBX scan root descriptor")
	}
	actual, err := uefiIdentityFromOpenFile(rootFile)
	if err != nil {
		rootFile.Close()
		return "", nil, fmt.Errorf("identify open DBX scan root: %w", err)
	}
	if !sameUEFIKernelObject(expected, actual) {
		rootFile.Close()
		return "", nil, errors.New("DBX scan root changed during validation")
	}
	return resolved, rootFile, nil
}

func walkDBXDirectory(ctx context.Context, directory *os.File, prefix string, depth int, limits *uefiTraversalLimits, hook uefiTraversalHook, files *[]uefiMediaFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readBoundedUEFIDirectory(ctx, directory, prefix, limits)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return fmt.Errorf("unsafe DBX scan directory entry name %q", name)
		}
		relative := filepath.ToSlash(filepath.Join(prefix, name))
		entryInfo, err := os.Lstat(filepath.Join(directory.Name(), name))
		if err != nil {
			return fmt.Errorf("stat DBX scan entry %s: %w", relative, err)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if entryInfo.IsDir() {
			if depth >= limits.maxDepth {
				return fmt.Errorf("DBX media tree exceeds the %d-level directory-depth safety limit at %s", limits.maxDepth, relative)
			}
			if hook != nil {
				hook("entry-before-open", relative)
			}
			child, err := openUEFIEntry(directory, name, entryInfo, true)
			if err != nil {
				return fmt.Errorf("open DBX scan directory %s: %w", relative, err)
			}
			err = walkDBXDirectory(ctx, child, relative, depth+1, limits, hook, files)
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return fmt.Errorf("close DBX scan directory %s: %w", relative, closeErr)
			}
			continue
		}
		if !isDBXBootFile(name) {
			continue
		}
		if !entryInfo.Mode().IsRegular() {
			continue
		}
		if len(*files) >= limits.maxFiles {
			return fmt.Errorf("more than %d EFI boot files found; refusing an unbounded scan", limits.maxFiles)
		}
		remaining := limits.maxTotalBytes - limits.totalBytes
		if entryInfo.Size() < 0 || entryInfo.Size() > remaining {
			return fmt.Errorf("EFI boot-file bytes exceed the %d-byte aggregate safety limit at %s", limits.maxTotalBytes, relative)
		}
		if hook != nil {
			hook("entry-before-open", relative)
		}
		file, err := openUEFIEntry(directory, name, entryInfo, false)
		if err != nil {
			return fmt.Errorf("open EFI boot file %s: %w", relative, err)
		}
		data, readErr := readStableUEFIFile(file)
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read EFI boot file %s: %w", relative, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close EFI boot file %s: %w", relative, closeErr)
		}
		if int64(len(data)) > remaining {
			return fmt.Errorf("EFI boot-file bytes exceed the %d-byte aggregate safety limit at %s", limits.maxTotalBytes, relative)
		}
		limits.totalBytes += int64(len(data))
		*files = append(*files, uefiMediaFile{relative: relative, data: data})
	}
	return nil
}

func isDBXBootFile(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".efi") || strings.EqualFold(name, "bootmgr")
}
