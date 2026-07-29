//go:build linux

package linuxmedia

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPlanExtractedLayoutForSchemeSupportsMBRAndGPT(t *testing.T) {
	const targetSize = uint64(768 * 1024 * 1024)
	mbr, err := PlanExtractedLayoutForScheme(targetSize, 512, 32*1024*1024, "mbr")
	if err != nil {
		t.Fatal(err)
	}
	gpt, err := PlanExtractedLayoutForScheme(targetSize, 512, 32*1024*1024, "gpt")
	if err != nil {
		t.Fatal(err)
	}
	if mbr.Partition.StartBytes != 1024*1024 || gpt.Partition.StartBytes != 1024*1024 {
		t.Fatalf("unexpected aligned starts: mbr=%+v gpt=%+v", mbr, gpt)
	}
	if gpt.Partition.SizeBytes >= mbr.Partition.SizeBytes {
		t.Fatalf("GPT did not reserve backup metadata: mbr=%d gpt=%d", mbr.Partition.SizeBytes, gpt.Partition.SizeBytes)
	}
	if err := validateExtractedGPTLayout(gpt); err != nil {
		t.Fatal(err)
	}
}

func TestWriteExtractedGPTWritesVerifiedEFIEntry(t *testing.T) {
	const targetSize = uint64(768 * 1024 * 1024)
	layout, err := PlanExtractedLayoutForScheme(targetSize, 512, 8*1024*1024, "gpt")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target.img")
	truncateLinuxTestFile(t, path, targetSize)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := WriteExtractedGPT(file, layout, "RUFUS-LIVE"); err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[446+4] != 0xee || sector[510] != 0x55 || sector[511] != 0xaa {
		t.Fatalf("unexpected protective MBR: %x", sector[446:462])
	}
	header := make([]byte, 512)
	if _, err := file.ReadAt(header, 512); err != nil {
		t.Fatal(err)
	}
	if string(header[:8]) != "EFI PART" {
		t.Fatalf("missing GPT signature: %q", header[:8])
	}
	entry := make([]byte, layoutGPTEntrySize)
	if _, err := file.ReadAt(entry, 2*512); err != nil {
		t.Fatal(err)
	}
	if string(entry[:16]) != string(layoutEFIType[:]) {
		t.Fatalf("unexpected partition type: %x", entry[:16])
	}
	if got := binary.LittleEndian.Uint64(entry[48:56]); got != 0 {
		t.Fatalf("ordinary ISO Image mode GPT partition unexpectedly has attributes %#x", got)
	}
}

func TestExtractedFAT32CapacityRejectsTooFewClusters(t *testing.T) {
	if err := validateExtractedFAT32Capacity(128*1024*1024, 32768); err == nil {
		t.Fatal("accepted a cluster size that cannot produce a valid FAT32 cluster count")
	}
	if err := validateExtractedFAT32Capacity(4*1024*1024*1024, 32768); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeExtractedClusterSize(t *testing.T) {
	for _, value := range []uint64{0, 4096, 8192, 16384, 32768} {
		if _, err := normalizeExtractedClusterSize(value, 512); err != nil {
			t.Fatalf("cluster %d rejected: %v", value, err)
		}
	}
	if _, err := normalizeExtractedClusterSize(65536, 512); err == nil {
		t.Fatal("accepted unsupported FAT32 cluster size")
	}
}
