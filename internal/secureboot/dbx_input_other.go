//go:build !linux

package secureboot

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func readStableDBXFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("DBX file size limit must be greater than zero")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open DBX file: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat DBX file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 {
		return nil, errors.New("DBX input must be a non-empty regular file")
	}
	if before.Size() > maxBytes {
		return nil, fmt.Errorf("DBX file is too large: %d bytes exceeds the %d-byte limit", before.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read DBX file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("DBX file exceeds the %d-byte limit", maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("restat DBX file: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != before.Size() {
		return nil, errors.New("DBX file changed while it was being read")
	}
	return data, nil
}
