//go:build linux

package uefintfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanLayoutCreatesAlignedTwoPartitionGeometry(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	for _, scheme := range []string{SchemeMBR, SchemeGPT} {
		layout, err := PlanLayout(scheme, targetSize, 512)
		if err != nil {
			t.Fatalf("PlanLayout(%s): %v", scheme, err)
		}
		if layout.Data.StartBytes%oneMiB != 0 || layout.Boot.StartBytes%oneMiB != 0 {
			t.Fatalf("%s layout is not MiB aligned: %+v", scheme, layout)
		}
		if layout.Boot.SizeBytes != ImageSize {
			t.Fatalf("%s boot size = %d", scheme, layout.Boot.SizeBytes)
		}
		if layout.Data.StartBytes+layout.Data.SizeBytes != layout.Boot.StartBytes {
			t.Fatalf("%s data/boot extents are not adjacent: %+v", scheme, layout)
		}
		if layout.Boot.StartBytes+layout.Boot.SizeBytes > targetSize {
			t.Fatalf("%s boot extent exceeds target: %+v", scheme, layout)
		}
	}
}

func TestWriteLayoutMBRPublishesAndReadsBackBothPartitions(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	layout, err := PlanLayout(SchemeMBR, targetSize, 512)
	if err != nil {
		t.Fatal(err)
	}
	target := createLayoutTarget(t, targetSize)
	defer target.Close()
	if err := WriteLayout(target, layout, "LINUXISO"); err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := target.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[510] != 0x55 || sector[511] != 0xaa {
		t.Fatal("missing MBR signature")
	}
	data := sector[446:462]
	boot := sector[462:478]
	if data[0] != 0x80 || data[4] != mbrDataPartition {
		t.Fatalf("data partition entry = %x", data)
	}
	if boot[0] != 0 || boot[4] != mbrUEFINTFSPartition {
		t.Fatalf("boot partition entry = %x", boot)
	}
	if got := uint64(binary.LittleEndian.Uint32(data[8:12])) * 512; got != layout.Data.StartBytes {
		t.Fatalf("data start = %d, want %d", got, layout.Data.StartBytes)
	}
	if got := uint64(binary.LittleEndian.Uint32(boot[8:12])) * 512; got != layout.Boot.StartBytes {
		t.Fatalf("boot start = %d, want %d", got, layout.Boot.StartBytes)
	}
}

func TestWriteLayoutGPTPublishesPrimaryAndBackupMetadata(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	layout, err := PlanLayout(SchemeGPT, targetSize, 512)
	if err != nil {
		t.Fatal(err)
	}
	target := createLayoutTarget(t, targetSize)
	defer target.Close()
	if err := WriteLayout(target, layout, "LINUXISO"); err != nil {
		t.Fatal(err)
	}
	primary := make([]byte, 512)
	backup := make([]byte, 512)
	if _, err := target.ReadAt(primary, 512); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ReadAt(backup, int64(targetSize-512)); err != nil {
		t.Fatal(err)
	}
	if string(primary[:8]) != "EFI PART" || string(backup[:8]) != "EFI PART" {
		t.Fatalf("GPT signatures primary=%q backup=%q", primary[:8], backup[:8])
	}
	if binary.LittleEndian.Uint64(primary[24:32]) != 1 || binary.LittleEndian.Uint64(backup[32:40]) != 1 {
		t.Fatalf("unexpected primary/backup linkage")
	}

	entries := make([]byte, gptEntryBytes*2)
	if _, err := target.ReadAt(entries, 2*512); err != nil {
		t.Fatal(err)
	}
	data := entries[:gptEntryBytes]
	boot := entries[gptEntryBytes:]
	if !bytes.Equal(data[:16], microsoftBasicDataType[:]) || !bytes.Equal(boot[:16], microsoftBasicDataType[:]) {
		t.Fatal("unexpected GPT partition type")
	}
	if got := binary.LittleEndian.Uint64(data[32:40]) * 512; got != layout.Data.StartBytes {
		t.Fatalf("data start = %d, want %d", got, layout.Data.StartBytes)
	}
	if got := binary.LittleEndian.Uint64(boot[32:40]) * 512; got != layout.Boot.StartBytes {
		t.Fatalf("boot start = %d, want %d", got, layout.Boot.StartBytes)
	}
	if binary.LittleEndian.Uint64(boot[48:56]) != gptNoDriveLetter {
		t.Fatal("UEFI:NTFS GPT partition is missing no-drive-letter attribute")
	}
	if !bytes.Contains(boot[56:128], []byte{'U', 0, 'E', 0, 'F', 0, 'I', 0}) {
		t.Fatal("UEFI:NTFS GPT partition name is missing")
	}
}

func TestWriteLayoutGPTMakesBackupDurableFirst(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	layout, err := PlanLayout(SchemeGPT, targetSize, 512)
	if err != nil {
		t.Fatal(err)
	}
	target := &recordingLayoutTarget{data: make([]byte, targetSize)}
	if err := WriteLayout(target, layout, "LINUXISO"); err != nil {
		t.Fatal(err)
	}
	firstSync := -1
	for index, event := range target.events {
		if event == "sync" {
			firstSync = index
			break
		}
	}
	if firstSync != 2 {
		t.Fatalf("events before first sync = %v", target.events)
	}
	for _, offset := range target.writeOffsets[:2] {
		if offset < targetSize/2 {
			t.Fatalf("primary metadata was written before backup durability: offsets=%v", target.writeOffsets)
		}
	}
	if len(target.writeOffsets) < 5 || target.writeOffsets[2] != 2*512 || target.writeOffsets[3] != 512 || target.writeOffsets[4] != 0 {
		t.Fatalf("unexpected GPT publication order: %v", target.writeOffsets)
	}
}

func TestLayoutRefusesInvalidGeometryAndChangedPlan(t *testing.T) {
	if _, err := PlanLayout(SchemeGPT, minimumLayoutBytes-512, 512); err == nil {
		t.Fatal("undersized GPT target was accepted")
	}
	if _, err := PlanLayout(SchemeMBR, 64*1024*1024, 1000); err == nil {
		t.Fatal("invalid sector size was accepted")
	}
	layout, err := PlanLayout(SchemeMBR, 64*1024*1024, 512)
	if err != nil {
		t.Fatal(err)
	}
	layout.Data.SizeBytes -= 512
	target := createLayoutTarget(t, layout.TargetSize)
	defer target.Close()
	if err := WriteLayout(target, layout, "LINUXISO"); err == nil || !strings.Contains(err.Error(), "deterministic planning") {
		t.Fatalf("WriteLayout() error = %v", err)
	}
}

func createLayoutTarget(t *testing.T, size uint64) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file
}

type recordingLayoutTarget struct {
	data         []byte
	events       []string
	writeOffsets []uint64
}

func (target *recordingLayoutTarget) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(target.data)) {
		return 0, io.EOF
	}
	n := copy(data, target.data[offset:])
	if n != len(data) {
		return n, io.EOF
	}
	return n, nil
}

func (target *recordingLayoutTarget) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset+int64(len(data)) > int64(len(target.data)) {
		return 0, io.ErrShortWrite
	}
	copy(target.data[offset:], data)
	target.events = append(target.events, "write")
	target.writeOffsets = append(target.writeOffsets, uint64(offset))
	return len(data), nil
}

func (target *recordingLayoutTarget) Sync() error {
	target.events = append(target.events, "sync")
	return nil
}
