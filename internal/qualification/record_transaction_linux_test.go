//go:build linux

package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRecordPreflightsChecksumBeforePublishingRecord(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, metadataDirName)
	if err := os.Mkdir(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	checksumPath := filepath.Join(metadata, RecordFileName+".sha256")
	original := []byte("pre-existing checksum\n")
	if err := os.WriteFile(checksumPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := WriteRecord(root, validRecord())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("pre-existing checksum was not refused: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(metadata, RecordFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("creation record was published before checksum preflight: %v", err)
	}
	current, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("pre-existing checksum was changed: %q", current)
	}
}

func TestWriteRecordPairRollsBackRecordAfterChecksumFailure(t *testing.T) {
	metadata := t.TempDir()
	recordPath := filepath.Join(metadata, RecordFileName)
	injected := errors.New("injected checksum publication failure")
	calls := 0
	writer := func(path string, data []byte, mode os.FileMode) error {
		calls++
		if calls == 2 {
			return injected
		}
		return writeAtomicNoFollow(path, data, mode)
	}

	err := writeRecordPairWith(recordPath, []byte("{}\n"), strings.Repeat("a", 64), writer)
	if !errors.Is(err, injected) {
		t.Fatalf("checksum failure was not returned: %v", err)
	}
	if calls != 2 {
		t.Fatalf("writer calls = %d, want 2", calls)
	}
	for _, path := range []string{recordPath, recordPath + ".sha256"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("partial metadata remained at %s: %v", path, statErr)
		}
	}
}
