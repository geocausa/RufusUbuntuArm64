package imaging

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectMBRImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	data := make([]byte, 64*1024)
	data[510], data[511] = 0x55, 0xaa
	data[446+4] = 0x0c
	data[446+8] = 1
	data[446+12] = 10
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
	data[16*2048+6] = 1
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
	for sector, identifier := range map[int]string{16: "BEA01", 17: "NSR03", 18: "TEA01"} {
		data[sector*2048] = 0
		copy(data[sector*2048+1:], identifier)
		data[sector*2048+6] = 1
	}
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

func TestInspectISOPrimaryDescriptorAfterBootDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootable.iso")
	data := make([]byte, 128*1024)
	data[16*2048] = 0 // boot record descriptor
	copy(data[16*2048+1:], "CD001")
	data[16*2048+6] = 1
	data[17*2048] = 1 // primary volume descriptor
	copy(data[17*2048+1:], "CD001")
	data[17*2048+6] = 1
	data[18*2048] = 255
	copy(data[18*2048+1:], "CD001")
	data[18*2048+6] = 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasISO9660 || !info.Recognized() {
		t.Fatalf("descriptor sequence was not recognized: %#v", info)
	}
}

func TestInspectRejectsArbitraryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(path, []byte("PK\\x03\\x04not an image"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Recognized() {
		t.Fatalf("arbitrary file was recognized: %#v", info)
	}
}

func TestInspectRejectsBareGPTString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.img")
	data := make([]byte, 64*1024)
	copy(data[512:], "EFI PART")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.HasGPT || info.Recognized() {
		t.Fatalf("bare GPT string was accepted: %#v", info)
	}
}

func TestInspectValidGPTHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpt.img")
	data := make([]byte, 2*1024*1024)
	copy(data[512:], "EFI PART")
	binary.LittleEndian.PutUint32(data[520:], 0x00010000)
	binary.LittleEndian.PutUint32(data[524:], 92)
	binary.LittleEndian.PutUint64(data[536:], 1)
	binary.LittleEndian.PutUint64(data[544:], 4095)
	binary.LittleEndian.PutUint64(data[552:], 34)
	binary.LittleEndian.PutUint64(data[560:], 4062)
	binary.LittleEndian.PutUint64(data[584:], 2)
	binary.LittleEndian.PutUint32(data[592:], 128)
	binary.LittleEndian.PutUint32(data[596:], 128)
	entryTable := data[2*512 : 2*512+128*128]
	entryTable[0] = 0x28 // non-zero partition type GUID
	binary.LittleEndian.PutUint32(data[600:], crc32.ChecksumIEEE(entryTable))
	header := append([]byte(nil), data[512:512+92]...)
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(data[528:], crc32.ChecksumIEEE(header))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasGPT || !info.LooksLikeRawBootMedia() {
		t.Fatalf("valid GPT header rejected: %#v", info)
	}
}

func TestInspectRejectsProtectiveMBRWithInvalidGPT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-gpt.img")
	data := make([]byte, 64*1024)
	data[510], data[511] = 0x55, 0xaa
	data[446+4] = 0xee
	binary.LittleEndian.PutUint32(data[446+8:], 1)
	binary.LittleEndian.PutUint32(data[446+12:], 100)
	copy(data[512:], "EFI PART")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Recognized() {
		t.Fatalf("invalid GPT was accepted through its protective MBR: %#v", info)
	}
}

func TestInspectRejectsMisalignedUDFSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.iso")
	data := make([]byte, 256*1024)
	copy(data[17*2048+123:], "NSR03")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.HasUDF || info.Recognized() {
		t.Fatalf("misaligned UDF string was accepted: %#v", info)
	}
}

func TestInspectRejectsGPTWithCorruptEntryTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpt-corrupt.img")
	data := make([]byte, 2*1024*1024)
	copy(data[512:], "EFI PART")
	binary.LittleEndian.PutUint32(data[520:], 0x00010000)
	binary.LittleEndian.PutUint32(data[524:], 92)
	binary.LittleEndian.PutUint64(data[536:], 1)
	binary.LittleEndian.PutUint64(data[544:], 4095)
	binary.LittleEndian.PutUint64(data[552:], 34)
	binary.LittleEndian.PutUint64(data[560:], 4062)
	binary.LittleEndian.PutUint64(data[584:], 2)
	binary.LittleEndian.PutUint32(data[592:], 128)
	binary.LittleEndian.PutUint32(data[596:], 128)
	entryTable := data[2*512 : 2*512+128*128]
	entryTable[0] = 0x28
	binary.LittleEndian.PutUint32(data[600:], crc32.ChecksumIEEE(entryTable)+1)
	header := append([]byte(nil), data[512:512+92]...)
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(data[528:], crc32.ChecksumIEEE(header))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.HasGPT || info.Recognized() {
		t.Fatalf("GPT with corrupt entry table was accepted: %#v", info)
	}
}
