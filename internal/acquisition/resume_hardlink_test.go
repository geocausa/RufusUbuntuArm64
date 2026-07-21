package acquisition

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDownloadPartialRejectsHardLinkedVictim(t *testing.T) {
	image := testImage("https://example.invalid/image.iso", []byte("signed image content that is longer than the victim"))
	directory := t.TempDir()
	destination := filepath.Join(directory, image.Filename)
	partial := resumePartialPath(destination, image)
	victim := filepath.Join(directory, "private-victim")
	original := []byte("private data")
	if err := os.WriteFile(victim, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, partial); err != nil {
		t.Fatal(err)
	}

	file, _, _, err := openDownloadPartial(destination, image, true)
	if file != nil {
		_ = file.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "exactly one link") {
		t.Fatalf("openDownloadPartial error = %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("hard-linked victim changed from %q to %q", original, data)
	}
	if _, err := os.Lstat(partial); err != nil {
		t.Fatalf("rejected partial pathname was removed: %v", err)
	}
}
