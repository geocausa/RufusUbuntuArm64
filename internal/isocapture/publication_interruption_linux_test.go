//go:build linux

package isocapture

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublishISONoReplaceRollsBackAfterDirectorySyncFailure(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".filesystem.iso.partial"
	const outputName = "filesystem.iso"
	if err := os.WriteFile(filepath.Join(path, temporaryName), []byte("verified filesystem ISO"), 0o600); err != nil {
		t.Fatal(err)
	}
	injectedSync := errors.New("injected ISO directory sync failure")
	syncCalls := 0
	err = publishISONoReplaceWith(directory, temporaryName, outputName, isoPublicationOps{
		rename: isoRenameNoReplaceAt,
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
		t.Fatalf("ISO publication sync failure = %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("ISO directory sync calls = %d, want 2", syncCalls)
	}
	for _, name := range []string{temporaryName, outputName} {
		if _, statErr := os.Lstat(filepath.Join(path, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("ISO publication artifact %s remains after successful rollback: %v", name, statErr)
		}
	}
}

func TestPublishISONoReplaceReportsAmbiguousRollbackFailure(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".filesystem.iso.partial"
	const outputName = "filesystem.iso"
	content := []byte("verified filesystem ISO")
	if err := os.WriteFile(filepath.Join(path, temporaryName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	injectedSync := errors.New("injected ISO directory sync failure")
	injectedUnlink := errors.New("injected ISO rollback unlink failure")
	injectedResync := errors.New("injected ISO rollback sync failure")
	syncCalls := 0
	err = publishISONoReplaceWith(directory, temporaryName, outputName, isoPublicationOps{
		rename: isoRenameNoReplaceAt,
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
			t.Fatalf("ambiguous ISO publication error %v does not include %v", err, expected)
		}
	}
	if syncCalls != 2 {
		t.Fatalf("ISO directory sync calls = %d, want 2", syncCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(path, temporaryName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("ISO temporary name remains after rename: %v", statErr)
	}
	published, readErr := os.ReadFile(filepath.Join(path, outputName))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(published) != string(content) {
		t.Fatalf("ambiguous published ISO content = %q", published)
	}
}

func TestPublishISONoReplaceRefusesSymlinkDestinationWithoutChangingTarget(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const temporaryName = ".filesystem.iso.partial"
	const outputName = "filesystem.iso"
	if err := os.WriteFile(filepath.Join(path, temporaryName), []byte("new ISO"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "outside-existing.iso")
	original := []byte("preserve existing ISO symlink target")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), filepath.Join(path, outputName)); err != nil {
		t.Fatal(err)
	}

	if err := publishISONoReplace(directory, temporaryName, outputName); err == nil {
		t.Fatal("ISO publication replaced a symbolic-link destination")
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("ISO symbolic-link target changed: %q", current)
	}
	info, err := os.Lstat(filepath.Join(path, outputName))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("ISO symbolic-link destination changed: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(filepath.Join(path, temporaryName)); err != nil {
		t.Fatalf("temporary ISO was lost after refused publication: %v", err)
	}
}
