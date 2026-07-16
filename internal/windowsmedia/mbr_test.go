//go:build linux

package windowsmedia

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/geocausa/RufusArm64/internal/imaging"
)

func TestWriteSinglePartitionMBR512(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	const size = uint64(64 * 1024 * 1024)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(size)); err != nil {
		t.Fatal(err)
	}
	layout, err := writeSinglePartitionMBR(f, size, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if layout.PartitionStartBytes != oneMiB {
		t.Fatalf("start=%d", layout.PartitionStartBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if data[510] != 0x55 || data[511] != 0xaa {
		t.Fatal("missing MBR signature")
	}
	entry := data[446:462]
	if entry[0] != 0x80 || entry[4] != 0x0c {
		t.Fatalf("bad MBR entry: %x", entry)
	}
	if got := binary.LittleEndian.Uint32(entry[8:12]); got != 2048 {
		t.Fatalf("start LBA=%d", got)
	}
	info, err := imaging.InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasMBR || info.HasGPT {
		t.Fatalf("inspection=%#v", info)
	}
}

func TestWriteSinglePartitionMBRFourKiB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	const size = uint64(64 * 1024 * 1024)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(size)); err != nil {
		t.Fatal(err)
	}
	layout, err := writeSinglePartitionMBR(f, size, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if layout.PartitionStartBytes != oneMiB {
		t.Fatalf("start=%d", layout.PartitionStartBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[454:458]); got != 256 {
		t.Fatalf("start LBA=%d", got)
	}
}

func TestWriteSinglePartitionMBRRejectsTooLarge(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "disk")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tooLarge := (uint64(^uint32(0)) + 4096) * 512
	if _, err := writeSinglePartitionMBR(f, tooLarge, 512); err == nil {
		t.Fatal("oversized MBR target accepted")
	}
}

func TestMBRLayoutValidationDoesNotNeedTarget(t *testing.T) {
	const size = uint64(64 * 1024 * 1024)
	layout, err := mbrLayoutForSize(size, 512)
	if err != nil {
		t.Fatal(err)
	}
	if layout.PartitionStartBytes != oneMiB || layout.PartitionSizeBytes == 0 {
		t.Fatalf("layout=%#v", layout)
	}
}

func TestWriteUEFINTFSMBR512(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk-ntfs.img")
	const (
		size          = uint64(64 * 1024 * 1024)
		bootImageSize = uint64(1024 * 1024)
	)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	layout, err := writeUEFINTFSMBR(file, size, 512, bootImageSize)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if layout.Boot == nil {
		file.Close()
		t.Fatal("missing UEFI:NTFS boot partition")
	}
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	dataEntry := sector[446:462]
	bootEntry := sector[462:478]
	if dataEntry[0] != 0x80 || dataEntry[4] != 0x07 {
		t.Fatalf("bad NTFS data entry: %x", dataEntry)
	}
	if bootEntry[0] != 0x00 || bootEntry[4] != 0xef {
		t.Fatalf("bad UEFI:NTFS boot entry: %x", bootEntry)
	}
	if got := uint64(binary.LittleEndian.Uint32(dataEntry[8:12])) * 512; got != layout.Data.PartitionStartBytes {
		t.Fatalf("data start=%d want %d", got, layout.Data.PartitionStartBytes)
	}
	if got := uint64(binary.LittleEndian.Uint32(bootEntry[8:12])) * 512; got != layout.Boot.PartitionStartBytes {
		t.Fatalf("boot start=%d want %d", got, layout.Boot.PartitionStartBytes)
	}
	if got := uint64(binary.LittleEndian.Uint32(bootEntry[12:16])) * 512; got != bootImageSize {
		t.Fatalf("boot size=%d want %d", got, bootImageSize)
	}
}
