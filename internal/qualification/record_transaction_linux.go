//go:build linux

package qualification

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type recordFileWriter func(string, []byte, os.FileMode) error

// writeRecordPair publishes the canonical creation record and its checksum as
// one recoverable pair. Multi-file publication cannot be atomic, so the second
// failure path removes only the first file published by this call and syncs the
// metadata directory before returning.
func writeRecordPair(recordPath string, data []byte, digest string) error {
	return writeRecordPairWith(recordPath, data, digest, writeAtomicNoFollow)
}

func writeRecordPairWith(recordPath string, data []byte, digest string, writeFile recordFileWriter) error {
	if writeFile == nil {
		return errors.New("creation record writer is nil")
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
		return fmt.Errorf("reinspect published creation record: %w", err)
	}
	if !published.Mode().IsRegular() {
		return errors.New("published creation record is not a regular file")
	}

	checksum := []byte(fmt.Sprintf("%s  %s\n", digest, filepath.Base(recordPath)))
	if err := writeFile(checksumPath, checksum, 0o600); err != nil {
		rollbackErr := removePublishedRecord(recordPath, published)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback creation record after checksum failure: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func requireMetadataDestinationAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("metadata file %s already exists", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func removePublishedRecord(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect creation record for rollback: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return errors.New("creation record changed before rollback; refusing to remove it")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove incomplete creation record: %w", err)
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
