//go:build linux

package windowsmedia

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingGPTTarget struct {
	*os.File
	operations []string
	sectorSize uint64
	targetSize uint64
}

func (target *recordingGPTTarget) WriteAt(data []byte, offset int64) (int, error) {
	entryBytes := uint64(gptEntryCount * gptEntrySize)
	entryLBAs := (entryBytes + target.sectorSize - 1) / target.sectorSize
	name := "other"
	switch uint64(offset) {
	case target.targetSize - (entryLBAs+1)*target.sectorSize:
		name = "backup-entries"
	case target.targetSize - target.sectorSize:
		name = "backup-header"
	case 2 * target.sectorSize:
		name = "primary-entries"
	case target.sectorSize:
		name = "primary-header"
	case 0:
		name = "protective-mbr"
	}
	target.operations = append(target.operations, name)
	return target.File.WriteAt(data, offset)
}

func (target *recordingGPTTarget) Sync() error {
	target.operations = append(target.operations, "sync")
	return target.File.Sync()
}

func TestWriteGPTMakesBackupDurableBeforePrimary(t *testing.T) {
	const (
		targetSize = uint64(64 * 1024 * 1024)
		sectorSize = uint64(512)
	)
	file := mustSizedGPTFile(t, targetSize)
	defer file.Close()
	target := &recordingGPTTarget{File: file, sectorSize: sectorSize, targetSize: targetSize}
	if _, err := writeGPT(target, targetSize, sectorSize, "WINDOWS", false, 0); err != nil {
		t.Fatal(err)
	}
	want := []string{"backup-entries", "backup-header", "sync", "primary-entries", "primary-header", "protective-mbr", "sync"}
	if strings.Join(target.operations, ",") != strings.Join(want, ",") {
		t.Fatalf("operation order=%v want=%v", target.operations, want)
	}
}

type corruptingGPTTarget struct {
	*os.File
	corruptOffset int64
}

func (target *corruptingGPTTarget) ReadAt(data []byte, offset int64) (int, error) {
	n, err := target.File.ReadAt(data, offset)
	if target.corruptOffset >= offset && target.corruptOffset < offset+int64(n) {
		data[target.corruptOffset-offset] ^= 0xff
	}
	return n, err
}

func TestWriteGPTRejectsReadbackCorruption(t *testing.T) {
	const (
		targetSize = uint64(64 * 1024 * 1024)
		sectorSize = uint64(512)
	)
	file := mustSizedGPTFile(t, targetSize)
	defer file.Close()
	target := &corruptingGPTTarget{File: file, corruptOffset: int64(sectorSize)}
	_, err := writeGPT(target, targetSize, sectorSize, "WINDOWS", false, 0)
	if err == nil || !strings.Contains(err.Error(), "readback") {
		t.Fatalf("readback corruption error = %v", err)
	}
}

func TestReadGPTMetadataAtRejectsShortRead(t *testing.T) {
	err := readGPTMetadataAt(shortGPTReader{}, make([]byte, 8), 0)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("short read error = %v", err)
	}
}

type shortGPTReader struct{}

func (shortGPTReader) ReadAt(data []byte, offset int64) (int, error) {
	if len(data) > 0 {
		data[0] = 1
		return 1, os.ErrNotExist
	}
	return 0, nil
}

func mustSizedGPTFile(t *testing.T, size uint64) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gpt-target.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file
}
