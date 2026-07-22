//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRecordDescriptorPairPublishesAndVerifies(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, metadataDirName)
	if err := os.Mkdir(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(metadata, RecordFileName)
	if err := writeRecordPairDescriptor(path, []byte("{}\n"), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{RecordFileName, RecordFileName + ".sha256"} {
		info, err := os.Lstat(filepath.Join(metadata, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", name, info.Mode())
		}
	}
}

func TestWriteRecordDescriptorPairRejectsMetadataSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, metadataDirName)
	if err := os.Mkdir(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(root, metadataDirName+"-displaced")
	outside := t.TempDir()
	path := filepath.Join(metadata, RecordFileName)

	err := writeRecordPairDescriptorWithHooks(
		path,
		[]byte("{}\n"),
		strings.Repeat("a", 64),
		metadataPairHooks{BetweenRecordAndChecksum: func() error {
			if err := os.Rename(metadata, displaced); err != nil {
				return err
			}
			return os.Symlink(outside, metadata)
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "directory changed before checksum publication") {
		t.Fatalf("metadata symlink swap error = %v", err)
	}
	assertMetadataDirectoryEmpty(t, displaced)
	assertMetadataDirectoryEmpty(t, outside)
}

func TestWriteRecordDescriptorPairRejectsMetadataDirectorySwap(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, metadataDirName)
	if err := os.Mkdir(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(root, metadataDirName+"-displaced")
	path := filepath.Join(metadata, RecordFileName)

	err := writeRecordPairDescriptorWithHooks(
		path,
		[]byte("{}\n"),
		strings.Repeat("b", 64),
		metadataPairHooks{BetweenRecordAndChecksum: func() error {
			if err := os.Rename(metadata, displaced); err != nil {
				return err
			}
			return os.Mkdir(metadata, 0o700)
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "directory changed before checksum publication") {
		t.Fatalf("metadata directory swap error = %v", err)
	}
	assertMetadataDirectoryEmpty(t, displaced)
	assertMetadataDirectoryEmpty(t, metadata)
}

func assertMetadataDirectoryEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("metadata escaped or rollback left files in %s: %v", path, entries)
	}
}
