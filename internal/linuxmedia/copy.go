//go:build linux

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
	"strings"
	"syscall"
)

type CopyEvent struct {
	Path  string
	Done  uint64
	Total uint64
}

type CopyOptions struct {
	Event func(CopyEvent)
}

// CopyAndVerify materializes a previously inspected manifest into an empty,
// private writable tree. Every file is copied through a same-directory
// temporary file, fsynced, atomically renamed, and then hashed from the
// destination before success is reported.
func CopyAndVerify(ctx context.Context, manifest Manifest, destinationRoot string, opts CopyOptions) (returnErr error) {
	if err := validateManifestForCopy(manifest); err != nil {
		return err
	}
	destinationRoot, err := prepareDestinationRoot(destinationRoot)
	if err != nil {
		return err
	}
	if pathsOverlap(manifest.SourceRoot, destinationRoot) {
		return errors.New("source and destination media trees must not overlap")
	}
	var done uint64
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative := filepath.FromSlash(entry.Path)
		if !filepath.IsLocal(relative) || relative == "." {
			return fmt.Errorf("unsafe manifest path %q", entry.Path)
		}
		destination := filepath.Join(destinationRoot, relative)
		if entry.SHA256 == "" {
			if err := safeMkdirAll(destinationRoot, relative, os.FileMode(entry.Mode)|0o700); err != nil {
				return fmt.Errorf("create directory %s: %w", entry.Path, err)
			}
			continue
		}
		if err := safeMkdirAll(destinationRoot, filepath.Dir(relative), 0o755); err != nil {
			return fmt.Errorf("create parent for %s: %w", entry.Path, err)
		}
		if err := copyEntry(ctx, entry, destination); err != nil {
			return fmt.Errorf("copy %s: %w", entry.Path, err)
		}
		done += entry.Size
		if opts.Event != nil {
			opts.Event(CopyEvent{Path: entry.Path, Done: done, Total: manifest.TotalBytes})
		}
	}
	for _, entry := range manifest.Entries {
		if entry.SHA256 == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		destination := filepath.Join(destinationRoot, filepath.FromSlash(entry.Path))
		digest, err := hashStableFile(ctx, destination, entry.Size)
		if err != nil {
			return fmt.Errorf("verify %s: %w", entry.Path, err)
		}
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("verify %s: SHA-256 mismatch", entry.Path)
		}
	}
	root, err := os.Open(destinationRoot)
	if err != nil {
		return err
	}
	if err := root.Sync(); err != nil {
		root.Close()
		return err
	}
	return root.Close()
}

func validateManifestForCopy(manifest Manifest) error {
	if manifest.SourceRoot == "" || len(manifest.Entries) == 0 {
		return errors.New("Linux media manifest is empty")
	}
	resolvedRoot, err := resolveRoot(manifest.SourceRoot)
	if err != nil {
		return fmt.Errorf("reopen manifest source root: %w", err)
	}
	if resolvedRoot != manifest.SourceRoot {
		return errors.New("manifest source root identity changed")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	var total uint64
	for _, entry := range manifest.Entries {
		relative := filepath.FromSlash(entry.Path)
		if !filepath.IsLocal(relative) || relative == "." {
			return fmt.Errorf("unsafe manifest path %q", entry.Path)
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate manifest path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if entry.SHA256 == "" {
			if entry.SourcePath != "" || entry.Size != 0 {
				return fmt.Errorf("directory manifest entry %q has file metadata", entry.Path)
			}
			continue
		}
		if len(entry.SHA256) != sha256.Size*2 {
			return fmt.Errorf("manifest entry %q has an invalid SHA-256", entry.Path)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return fmt.Errorf("manifest entry %q has an invalid SHA-256", entry.Path)
		}
		sourceRelative, err := filepath.Rel(manifest.SourceRoot, entry.SourcePath)
		if err != nil || !filepath.IsLocal(sourceRelative) || sourceRelative == "." {
			return fmt.Errorf("manifest source for %q escapes the source root", entry.Path)
		}
		if entry.Size > ^uint64(0)-total {
			return errors.New("manifest byte total overflows")
		}
		total += entry.Size
	}
	if total != manifest.TotalBytes {
		return fmt.Errorf("manifest byte total changed: entries=%d manifest=%d", total, manifest.TotalBytes)
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	leftToRight, leftErr := filepath.Rel(left, right)
	rightToLeft, rightErr := filepath.Rel(right, left)
	return (leftErr == nil && (leftToRight == "." || filepath.IsLocal(leftToRight) && !strings.HasPrefix(leftToRight, ".."+string(os.PathSeparator)))) ||
		(rightErr == nil && (rightToLeft == "." || filepath.IsLocal(rightToLeft) && !strings.HasPrefix(rightToLeft, ".."+string(os.PathSeparator))))
}

func prepareDestinationRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("destination root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("destination root must be a real directory")
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return "", err
	}
	if len(entries) != 0 {
		return "", errors.New("destination root must be empty")
	}
	return absolute, nil
}

func safeMkdirAll(root, relative string, mode os.FileMode) error {
	if relative == "." || relative == "" {
		return nil
	}
	if !filepath.IsLocal(relative) {
		return errors.New("unsafe destination path")
	}
	current := root
	parts := strings.Split(filepath.Clean(relative), string(os.PathSeparator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("unsafe destination path component")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			createMode := os.FileMode(0o755)
			if current == filepath.Join(root, relative) && mode != 0 {
				createMode = mode
			}
			if err := os.Mkdir(current, createMode); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("destination component %s is not a real directory", current)
		}
	}
	return nil
}

func copyEntry(ctx context.Context, entry Entry, destination string) (returnErr error) {
	if entry.SourcePath == "" {
		return errors.New("manifest source path is missing")
	}
	source, err := os.Open(entry.SourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	lstat, err := os.Lstat(entry.SourcePath)
	if err != nil {
		return err
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return errors.New("manifest source is no longer a real regular file")
	}
	before, err := source.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || uint64(before.Size()) != entry.Size || !sameIdentity(lstat, before) {
		return errors.New("source identity no longer matches the manifest")
	}
	parent := filepath.Dir(destination)
	temporary, err := os.CreateTemp(parent, ".rufus-linux-copy-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		if temporary != nil {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(os.FileMode(entry.Mode)); err != nil {
		return err
	}
	hash := sha256.New()
	writer := io.MultiWriter(temporary, hash)
	buffer := make([]byte, copyBufferSize)
	var copied uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			written, writeErr := writer.Write(buffer[:n])
			copied += uint64(written)
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if copied != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return errors.New("source bytes no longer match the manifest")
	}
	after, err := source.Stat()
	if err != nil {
		return err
	}
	if !sameIdentity(before, after) {
		return errors.New("source changed during copy")
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return err
	}
	temporary = nil
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("destination file already exists")
		}
		return err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return err
	}
	parentHandle, err := os.Open(parent)
	if err != nil {
		return err
	}
	if err := parentHandle.Sync(); err != nil {
		parentHandle.Close()
		return err
	}
	return parentHandle.Close()
}

func openDirectoryNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
