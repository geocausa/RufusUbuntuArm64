package persistence

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyMBRPartitionPlan(t *testing.T) {
	imageSize := uint64(64 * testMiB)
	targetSize := uint64(4 * 1024 * testMiB)
	path := filepath.Join(t.TempDir(), "target.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(targetSize)); err != nil {
		t.Fatal(err)
	}
	mbr := make([]byte, 512)
	mbr[510], mbr[511] = 0x55, 0xaa
	entry := mbr[446:462]
	entry[4] = 0x17
	binary.LittleEndian.PutUint32(entry[8:12], 64)
	binary.LittleEndian.PutUint32(entry[12:16], uint32(imageSize/512-64))
	if _, err := file.WriteAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(file, imageSize, targetSize, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPartitionPlan(file, imageSize, targetSize, plan, MaterializeOptions{}); err != nil {
		t.Fatal(err)
	}
	written := make([]byte, 512)
	if _, err := file.ReadAt(written, 0); err != nil {
		t.Fatal(err)
	}
	newEntry := written[446+16 : 446+32]
	if newEntry[4] != 0x83 || binary.LittleEndian.Uint32(newEntry[8:12]) != uint32(plan.StartBytes/512) || binary.LittleEndian.Uint32(newEntry[12:16]) != uint32(plan.SizeBytes/512) {
		t.Fatalf("unexpected MBR entry: %x", newEntry)
	}
}

func TestApplyPartitionPlanRejectsChangedTarget(t *testing.T) {
	imageSize := uint64(64 * testMiB)
	targetSize := uint64(4 * 1024 * testMiB)
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	plan, err := BuildPlan(bytes.NewReader(image), imageSize, targetSize, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	image[446+4] = 0x17
	binary.LittleEndian.PutUint32(image[446+8:], 2048)
	binary.LittleEndian.PutUint32(image[446+12:], 4096)
	if err := ApplyPartitionPlan(bytesReadWriterAt{data: image}, imageSize, targetSize, plan, MaterializeOptions{}); err == nil {
		t.Fatal("changed partition table accepted")
	}
}

func TestApplyGPTPartitionPlanRelocatesBackup(t *testing.T) {
	image, imageSize := testGPTImage(t, 128, false)
	targetSize := uint64(8 * 1024 * testMiB)
	path := filepath.Join(t.TempDir(), "target.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(targetSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(image, 0); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(file, imageSize, targetSize, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	if err := ApplyPartitionPlan(file, imageSize, targetSize, plan, MaterializeOptions{Random: entropy}); err != nil {
		t.Fatal(err)
	}

	primaryBytes := make([]byte, 512)
	if _, err := file.ReadAt(primaryBytes, 512); err != nil {
		t.Fatal(err)
	}
	primary, err := parseGPTHeader(primaryBytes, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if primary.BackupLBA != targetSize/512-1 {
		t.Fatalf("backup LBA=%d", primary.BackupLBA)
	}
	entriesBytes := uint64(primary.NumEntries) * uint64(primary.EntrySize)
	entries := make([]byte, entriesBytes)
	if _, err := file.ReadAt(entries, int64(primary.EntriesLBA*512)); err != nil {
		t.Fatal(err)
	}
	if crc32.ChecksumIEEE(entries) != primary.EntriesCRC {
		t.Fatal("entry CRC mismatch")
	}
	offset := uint64(plan.PartitionNumber-1) * uint64(primary.EntrySize)
	entry := entries[offset : offset+uint64(primary.EntrySize)]
	if !bytes.Equal(entry[:16], linuxFilesystemDataGUID[:]) {
		t.Fatalf("type GUID=%x", entry[:16])
	}
	if binary.LittleEndian.Uint64(entry[32:40])*512 != plan.StartBytes || (binary.LittleEndian.Uint64(entry[40:48])-binary.LittleEndian.Uint64(entry[32:40])+1)*512 != plan.SizeBytes {
		t.Fatalf("wrong GPT extent: %x", entry[32:48])
	}
	oldBackup := make([]byte, 512)
	if _, err := file.ReadAt(oldBackup, int64(imageSize-512)); err != nil {
		t.Fatal(err)
	}
	if !allZero(oldBackup) {
		t.Fatal("obsolete backup GPT header was not cleared")
	}
}

type bytesReadWriterAt struct {
	data []byte
}

func (memory bytesReadWriterAt) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(memory.data)) {
		return 0, os.ErrInvalid
	}
	n := copy(p, memory.data[offset:])
	if n != len(p) {
		return n, os.ErrInvalid
	}
	return n, nil
}

func (memory bytesReadWriterAt) WriteAt(p []byte, offset int64) (int, error) {
	if offset < 0 || offset+int64(len(p)) > int64(len(memory.data)) {
		return 0, os.ErrInvalid
	}
	return copy(memory.data[offset:], p), nil
}
