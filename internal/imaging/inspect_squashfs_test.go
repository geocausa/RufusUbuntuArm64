package imaging

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRecognizesDirectSquashFSSuperblock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filesystem.squashfs")
	data := make([]byte, 64*1024)
	copy(data, "hsqs")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasSquashFS || !info.HasDirectFilesystem() || !info.Recognized() {
		t.Fatalf("direct SquashFS superblock was not recognized: %#v", info)
	}
	if info.HasOpticalFilesystem() || info.LooksLikeRawBootMedia() {
		t.Fatalf("bare SquashFS was promoted to optical or raw-bootable media: %#v", info)
	}
}

func TestInspectRejectsMisalignedSquashFSMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "misaligned.bin")
	data := make([]byte, 64*1024)
	copy(data[4096:], "hsqs")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.HasSquashFS || info.Recognized() {
		t.Fatalf("misaligned SquashFS string was accepted: %#v", info)
	}
}

func TestInspectSquashFSWithinMBRImagePreservesRawBootClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hybrid.img")
	data := make([]byte, 2*1024*1024)
	copy(data, "hsqs")
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], 1024)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasSquashFS || !info.LooksLikeRawBootMedia() {
		t.Fatalf("SquashFS-backed MBR image lost raw-media classification: %#v", info)
	}
}
