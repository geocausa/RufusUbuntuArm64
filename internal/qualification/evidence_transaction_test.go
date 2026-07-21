//go:build linux

package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteEvidencePreflightsChecksumBeforePublishingEvidence(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "qualification.json")
	checksumPath := output + ".sha256"
	original := []byte("pre-existing checksum\n")
	if err := os.WriteFile(checksumPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := WriteEvidence(output, Evidence{Phase: "verified", GeneratedAt: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("pre-existing checksum was not refused: %v", err)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence was published before checksum preflight: %v", statErr)
	}
	current, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("pre-existing checksum was changed: %q", current)
	}
}

func TestEvidencePairRollsBackAfterChecksumPublicationFailure(t *testing.T) {
	output := filepath.Join(t.TempDir(), "qualification.json")
	injected := errors.New("injected evidence checksum failure")
	calls := 0
	writer := func(path string, data []byte, mode os.FileMode) error {
		calls++
		if calls == 2 {
			return injected
		}
		return writeAtomicNoFollow(path, data, mode)
	}

	err := writeRecordPairWith(output, []byte("{}\n"), strings.Repeat("b", 64), writer)
	if !errors.Is(err, injected) {
		t.Fatalf("checksum failure was not returned: %v", err)
	}
	for _, path := range []string{output, output + ".sha256"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("partial evidence remained at %s: %v", path, statErr)
		}
	}
}
