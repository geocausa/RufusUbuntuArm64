//go:build linux

package qualification

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type recordFileWriter func(string, []byte, os.FileMode) error

// writeRecordPair publishes one metadata document and its checksum as a
// recoverable pair. Multi-file publication cannot be atomic, so the second
// failure path removes only the first file published by this call and syncs the
// metadata directory before returning.
func writeRecordPair(recordPath string, data []byte, digest string) error {
	return writeRecordPairWith(recordPath, data, digest, writeAtomicNoFollow)
}

func writeRecordPairWith(recordPath string, data []byte, digest string, writeFile recordFileWriter) error {
	description := metadataDocumentDescription(recordPath)
	if writeFile == nil {
		return fmt.Errorf("%s writer is nil", description)
	}
	checksumPath := recordPath + ".sha256"
	for _, path := range []string{recordPath, checksumPath} {
		if err := requireMetadataDestinationAbsent(path); err != nil {
			return err
		}
	}

	if err := writeFile(recordPath, data, 0o600); err != nil {
		return err
	}
	published, err := os.Lstat(recordPath)
	if err != nil {
		return fmt.Errorf("reinspect published %s: %w", description, err)
	}
	if !published.Mode().IsRegular() {
		return fmt.Errorf("published %s is not a regular file", description)
	}

	checksum := []byte(fmt.Sprintf("%s  %s\n", digest, filepath.Base(recordPath)))
	if err := writeFile(checksumPath, checksum, 0o600); err != nil {
		rollbackErr := removePublishedRecord(recordPath, published, description)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback %s after checksum failure: %w", description, rollbackErr))
		}
		return err
	}
	return nil
}

func metadataDocumentDescription(path string) string {
	if filepath.Base(path) == RecordFileName {
		return "creation record"
	}
	return "qualification evidence"
}

func requireMetadataDestinationAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("metadata file %s already exists", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func removePublishedRecord(path string, expected os.FileInfo, description string) error {
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect %s for rollback: %w", description, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return fmt.Errorf("%s changed before rollback; refusing to remove it", description)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove incomplete %s: %w", description, err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open metadata directory after rollback: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync metadata directory after rollback: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close metadata directory after rollback: %w", err)
	}
	return nil
}
