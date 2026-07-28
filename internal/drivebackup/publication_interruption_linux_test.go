//go:build linux

package drivebackup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublishNoReplaceRollsBackAfterDirectorySyncFailure(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".drive.img.partial"
	const outputName = "drive.img"
	if err := os.WriteFile(filepath.Join(path, temporaryName), []byte("verified capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	injectedSync := errors.New("injected publication directory sync failure")
	syncCalls := 0
	err = publishNoReplaceWith(directory, temporaryName, outputName, publicationOps{
		rename: renameNoReplaceAt,
		sync: func(open *os.File) error {
			syncCalls++
			if syncCalls == 1 {
				return injectedSync
			}
			return open.Sync()
		},
		unlink: func(open *os.File, name string) error {
			return syscall.Unlinkat(int(open.Fd()), name)
		},
	})
	if !errors.Is(err, injectedSync) {
		t.Fatalf("publication sync failure = %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", syncCalls)
	}
	for _, name := range []string{temporaryName, outputName} {
		if _, statErr := os.Lstat(filepath.Join(path, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("publication artifact %s remains after successful rollback: %v", name, statErr)
		}
	}
}

func TestPublishNoReplaceReportsAmbiguousRollbackFailure(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".drive.img.partial"
	const outputName = "drive.img"
	content := []byte("verified capture")
	if err := os.WriteFile(filepath.Join(path, temporaryName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	injectedSync := errors.New("injected publication directory sync failure")
	injectedUnlink := errors.New("injected publication rollback unlink failure")
	injectedResync := errors.New("injected publication rollback sync failure")
	syncCalls := 0
	err = publishNoReplaceWith(directory, temporaryName, outputName, publicationOps{
		rename: renameNoReplaceAt,
		sync: func(*os.File) error {
			syncCalls++
			if syncCalls == 1 {
				return injectedSync
			}
			return injectedResync
		},
		unlink: func(*os.File, string) error { return injectedUnlink },
	})
	for _, expected := range []error{injectedSync, injectedUnlink, injectedResync} {
		if !errors.Is(err, expected) {
			t.Fatalf("ambiguous publication error %v does not include %v", err, expected)
		}
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", syncCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(path, temporaryName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary name remains after rename: %v", statErr)
	}
	published, readErr := os.ReadFile(filepath.Join(path, outputName))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(published) != string(content) {
		t.Fatalf("ambiguous published content = %q", published)
	}
}

func TestPublishNoReplaceRefusesSymlinkDestinationWithoutChangingTarget(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".drive.img.partial"
	const outputName = "drive.img"
	if err := os.WriteFile(filepath.Join(path, temporaryName), []byte("new capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "outside-existing.img")
	original := []byte("preserve existing symlink target")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), filepath.Join(path, outputName)); err != nil {
		t.Fatal(err)
	}

	if err := publishNoReplace(directory, temporaryName, outputName); err == nil {
		t.Fatal("publication replaced a symbolic-link destination")
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("symbolic-link target changed: %q", current)
	}
	info, err := os.Lstat(filepath.Join(path, outputName))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symbolic-link destination changed: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(filepath.Join(path, temporaryName)); err != nil {
		t.Fatalf("temporary capture was lost after refused publication: %v", err)
	}
}
