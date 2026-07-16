package sourcefile

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
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
