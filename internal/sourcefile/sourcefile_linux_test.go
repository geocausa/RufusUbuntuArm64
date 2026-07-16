//go:build linux

package sourcefile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectAndOpenRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
}

func TestOpenRegularRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegular(resolved, identity); err == nil {
		file.Close()
		t.Fatal("replacement was accepted")
	}
}

func TestOpenRegularRejectsInPlaceChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegular(resolved, identity); err == nil {
		file.Close()
		t.Fatal("changed image was accepted")
	}
}

func TestVerifyToleratesMetadataOnlyChangesOnPinnedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("pinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := IdentityOf(file)
	if err != nil {
		t.Fatal(err)
	}
	// Cross a kernel timestamp tick so ctime-affecting operations below are
	// guaranteed to change the inode change time.
	time.Sleep(25 * time.Millisecond)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.img")
	if err := os.WriteFile(replacement, []byte("another file"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Renaming over the path drops the pinned inode's link count, which
	// updates its ctime. The pinned descriptor still reads the confirmed
	// bytes, so verification must keep succeeding.
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinned(file, identity); err != nil {
		t.Fatalf("metadata-only change invalidated a pinned source: %v", err)
	}
}

func TestStrictVerifyRejectsRestoredMtimeContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("AAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := IdentityOf(file)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if err := os.WriteFile(path, []byte("BBBB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := Verify(file, identity); err == nil {
		t.Fatal("strict identity accepted a same-size edit with restored mtime")
	}
}
