//go:build linux

package linuxmedia

import (
	"os"
	"testing"
)

func TestPlanISOImageLayoutUsesOneAlignedFAT32Partition(t *testing.T) {
	const targetSize = uint64(8 * 1024 * 1024 * 1024)
	const required = uint64(5 * 1024 * 1024 * 1024)
	layout, err := PlanISOImageLayout(targetSize, 512, required)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Partition.Number != 1 || layout.Partition.StartBytes%layoutAlignment != 0 {
		t.Fatalf("unexpected partition layout: %#v", layout)
	}
	if layout.Partition.SizeBytes < required+minimumISOImageHeadroom {
		t.Fatalf("partition lacks required headroom: %#v", layout)
	}
	if layout.Partition.StartBytes+layout.Partition.SizeBytes >= targetSize {
		t.Fatalf("partition did not reserve backup GPT metadata: %#v", layout)
	}
}

func TestPlanISOImageLayoutRejectsInsufficientCapacity(t *testing.T) {
	if _, err := PlanISOImageLayout(1024*1024*1024, 512, 1000*1024*1024); err == nil {
		t.Fatal("accepted a target without required FAT32 headroom")
	}
	if _, err := PlanISOImageLayout(minimumISOImageDiskSize-512, 512, 1); err == nil {
		t.Fatal("accepted a target below the minimum ISO Image mode size")
	}
}

func TestWriteISOImageGPTReadsBackExactMetadata(t *testing.T) {
	const targetSize = uint64(2 * 1024 * 1024 * 1024)
	layout, err := PlanISOImageLayout(targetSize, 512, 64*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/target.img"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(targetSize)); err != nil {
		t.Fatal(err)
	}
	if err := WriteISOImageGPT(file, layout, "RUFUS-LIVE"); err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[510] != 0x55 || sector[511] != 0xaa || sector[450] != 0xee {
		t.Fatalf("protective MBR is invalid: %x", sector[446:462])
	}
}
