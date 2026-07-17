package sourcefile

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSHA256OpenRestoresOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	content := []byte("abcdef")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(3, 0); err != nil {
		t.Fatal(err)
	}
	var lastDone, lastTotal uint64
	got, err := SHA256Open(context.Background(), file, func(done, total uint64) {
		lastDone, lastTotal = done, total
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if got != want {
		t.Fatalf("digest=%x want %x", got, want)
	}
	position, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if position != 3 {
		t.Fatalf("offset=%d want 3", position)
	}
	if lastDone != uint64(len(content)) || lastTotal != uint64(len(content)) {
		t.Fatalf("progress=%d/%d", lastDone, lastTotal)
	}
}

func TestSHA256OpenRejectsNilContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	//lint:ignore SA1012 This regression test deliberately verifies that nil contexts fail closed.
	if _, err := SHA256Open(nil, file, nil); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil-context error = %v", err)
	}
}

func TestSHA256OpenRejectsShrinkDuringHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	const originalSize = int64(3 * digestBufferSize)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(originalSize); err != nil {
		t.Fatal(err)
	}
	mutated := false
	_, err = SHA256Open(context.Background(), file, func(done, total uint64) {
		if !mutated && done >= digestBufferSize {
			mutated = true
			if truncateErr := os.Truncate(path, int64(digestBufferSize)); truncateErr != nil {
				t.Errorf("truncate during hash: %v", truncateErr)
			}
		}
	})
	if err == nil || !strings.Contains(err.Error(), "size changed") {
		t.Fatalf("shrink error = %v", err)
	}
	if !mutated {
		t.Fatal("test did not mutate the file")
	}
}
