package imaging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectMBRImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	data := make([]byte, 64*1024)
	data[510], data[511] = 0x55, 0xaa
	data[446+4] = 0x0c
	data[446+12] = 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasMBR || !info.HasMBRPartition || !info.LooksLikeRawBootMedia() {
		t.Fatalf("unexpected inspection: %#v", info)
	}
}

func TestInspectPlainISO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.iso")
	data := make([]byte, 64*1024)
	data[16*2048] = 1
	copy(data[16*2048+1:], "CD001")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasISO9660 || info.LooksLikeRawBootMedia() {
		t.Fatalf("unexpected inspection: %#v", info)
	}
}

func TestInspectUDF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "windows.iso")
	data := make([]byte, 256*1024)
	copy(data[17*2048:], "NSR03")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasUDF || !info.HasOpticalFilesystem() {
		t.Fatalf("unexpected inspection: %#v", info)
	}
}
