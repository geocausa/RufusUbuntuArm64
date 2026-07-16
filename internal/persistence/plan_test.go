package persistence

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

const testMiB = uint64(1024 * 1024)

func readyDetection() Detection {
	return Detection{Family: FamilyDebianLive, BootParameter: "persistence", Filesystem: "ext4", FilesystemLabel: "persistence", PersistenceConfig: "/ union\n", PatchPaths: []string{"boot/grub/grub.cfg"}}
}

func TestBuildMBRPlan(t *testing.T) {
	imageSize := 64 * testMiB
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0x17
	binary.LittleEndian.PutUint32(image[446+8:], 64)
	binary.LittleEndian.PutUint32(image[446+12:], uint32(imageSize/512-64))
	plan, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	if plan.PartitionTable != TableMBR || plan.PartitionNumber != 2 || plan.StartBytes != imageSize || plan.SizeBytes != 2*1024*testMiB || plan.RequiresGPTRelocation {
		t.Fatalf("unexpected MBR plan: %#v", plan)
	}
}

func TestBuildMBRPlanUsesRemainingSpace(t *testing.T) {
	imageSize := 65 * testMiB
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	plan, err := BuildPlan(bytes.NewReader(image), imageSize, 4*1024*testMiB, 0, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	if plan.StartBytes != 65*testMiB || plan.SizeBytes != 4*1024*testMiB-65*testMiB {
		t.Fatalf("unexpected all-space plan: %#v", plan)
	}
}

func TestBuildPlanRejectsOverlappingMBRPartitions(t *testing.T) {
	image := make([]byte, 64*testMiB)
	image[510], image[511] = 0x55, 0xaa
	for index, extent := range [][2]uint32{{2048, 8192}, {4096, 8192}} {
		entry := image[446+index*16 : 446+(index+1)*16]
		entry[4] = 0x17
		binary.LittleEndian.PutUint32(entry[8:12], extent[0])
		binary.LittleEndian.PutUint32(entry[12:16], extent[1])
	}
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("overlapping MBR partitions accepted")
	}
}

func TestBuildPlanRejectsMBRExtentBeyondTwoTiB(t *testing.T) {
	imageSize := 64 * testMiB
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	targetSize := (uint64(1)<<32)*512 + 2*testMiB
	if _, err := BuildPlan(bytes.NewReader(image), imageSize, targetSize, 0, readyDetection()); err == nil {
		t.Fatal("unrepresentable MBR persistence extent accepted")
	}
}

func TestBuildPlanRejectsFullMBR(t *testing.T) {
	image := make([]byte, 64*testMiB)
	image[510], image[511] = 0x55, 0xaa
	for index := 0; index < 4; index++ {
		image[446+index*16+4] = 0x17
		binary.LittleEndian.PutUint32(image[446+index*16+8:], uint32(64+index*100))
		binary.LittleEndian.PutUint32(image[446+index*16+12:], 50)
	}
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("full MBR accepted")
	}
}

func TestBuildGPTPlan(t *testing.T) {
	image, imageSize := testGPTImage(t, 128, false)
	plan, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	if plan.PartitionTable != TableGPT || plan.PartitionNumber != 2 || !plan.RequiresGPTRelocation || plan.SizeBytes != 2*1024*testMiB {
		t.Fatalf("unexpected GPT plan: %#v", plan)
	}
}

func TestBuildPlanRejectsFullGPT(t *testing.T) {
	image, imageSize := testGPTImage(t, 2, true)
	if _, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("full GPT accepted")
	}
}

func TestBuildPlanRejectsSmallTarget(t *testing.T) {
	image := make([]byte, 64*testMiB)
	image[510], image[511] = 0x55, 0xaa
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 512*testMiB, 0, readyDetection()); err == nil {
		t.Fatal("undersized target accepted")
	}
}

func TestBuildPlanRejectsIncompleteDetection(t *testing.T) {
	image := make([]byte, 64*testMiB)
	image[510], image[511] = 0x55, 0xaa
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 8*1024*testMiB, 0, Detection{}); err == nil {
		t.Fatal("incomplete detection accepted")
	}
}

func testGPTImage(t *testing.T, entries uint32, fillAll bool) ([]byte, uint64) {
	t.Helper()
	imageSize := 64 * testMiB
	image := make([]byte, imageSize)
	imageSectors := imageSize / 512
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0xee
	binary.LittleEndian.PutUint32(image[446+8:], 1)
	binary.LittleEndian.PutUint32(image[446+12:], uint32(imageSectors-1))

	entryBytes := uint64(entries) * 128
	entrySectors := (entryBytes + 511) / 512
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := imageSectors - 1
	backupEntriesLBA := backupHeaderLBA - entrySectors
	firstUsable := primaryEntriesLBA + entrySectors
	lastUsable := backupEntriesLBA - 1

	table := image[primaryEntriesLBA*512 : primaryEntriesLBA*512+entryBytes]
	for index := uint32(0); index < entries; index++ {
		if index == 0 || fillAll {
			entry := table[index*128 : (index+1)*128]
			entry[0] = byte(index + 1)
			entry[16] = byte(index + 1)
			first := uint64(2048) + uint64(index)*4096
			last := first + 2047
			binary.LittleEndian.PutUint64(entry[32:40], first)
			binary.LittleEndian.PutUint64(entry[40:48], last)
		}
	}
	entriesCRC := crc32.ChecksumIEEE(table)
	backupTable := image[backupEntriesLBA*512 : backupEntriesLBA*512+entryBytes]
	copy(backupTable, table)

	diskGUID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	writeGPTHeader := func(header []byte, current, backup, entriesLBA uint64) {
		copy(header, "EFI PART")
		binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
		binary.LittleEndian.PutUint32(header[12:16], 92)
		binary.LittleEndian.PutUint64(header[24:32], current)
		binary.LittleEndian.PutUint64(header[32:40], backup)
		binary.LittleEndian.PutUint64(header[40:48], firstUsable)
		binary.LittleEndian.PutUint64(header[48:56], lastUsable)
		copy(header[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
		binary.LittleEndian.PutUint32(header[80:84], entries)
		binary.LittleEndian.PutUint32(header[84:88], 128)
		binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
		headerCopy := append([]byte(nil), header[:92]...)
		binary.LittleEndian.PutUint32(headerCopy[16:20], 0)
		binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(headerCopy))
	}
	writeGPTHeader(image[512:1024], 1, backupHeaderLBA, primaryEntriesLBA)
	writeGPTHeader(image[backupHeaderLBA*512:(backupHeaderLBA+1)*512], backupHeaderLBA, 1, backupEntriesLBA)
	return image, imageSize
}

func TestParseSize(t *testing.T) {
	for input, want := range map[string]uint64{"0": 0, "1024": 1024, "1G": 1 << 30, "2GiB": 2 << 30, "3m": 3 << 20, "512B": 512} {
		got, err := ParseSize(input)
		if err != nil || got != want {
			t.Fatalf("ParseSize(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"1.5G", "-1", "GB", "18446744073709551615T"} {
		if _, err := ParseSize(input); err == nil {
			t.Fatalf("invalid size %q accepted", input)
		}
	}
}

func TestBuildPlanRejectsUnalignedGeometry(t *testing.T) {
	image := make([]byte, 64*testMiB+1)
	image[510], image[511] = 0x55, 0xaa
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 4*1024*testMiB, 0, readyDetection()); err == nil {
		t.Fatal("unaligned image size accepted")
	}
	image = image[:64*testMiB]
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 4*1024*testMiB+1, 0, readyDetection()); err == nil {
		t.Fatal("unaligned target size accepted")
	}
	if _, err := BuildPlan(bytes.NewReader(image), uint64(len(image)), 4*1024*testMiB, 1024*testMiB+512, readyDetection()); err == nil {
		t.Fatal("unaligned requested persistence size accepted")
	}
}

func TestBuildPlanRejectsInconsistentBackupGPT(t *testing.T) {
	image, imageSize := testGPTImage(t, 128, false)
	backupHeaderOffset := imageSize - 512
	image[backupHeaderOffset+56] ^= 0xff
	if _, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("corrupted backup GPT accepted")
	}
}

func TestBuildPlanRejectsOverlappingGPTPartitions(t *testing.T) {
	image, imageSize := testGPTImage(t, 3, false)
	primaryHeader := image[512:1024]
	entriesLBA := binary.LittleEndian.Uint64(primaryHeader[72:80])
	entrySize := binary.LittleEndian.Uint32(primaryHeader[84:88])
	second := image[entriesLBA*512+uint64(entrySize) : entriesLBA*512+2*uint64(entrySize)]
	second[0], second[16] = 2, 2
	binary.LittleEndian.PutUint64(second[32:40], 3000)
	binary.LittleEndian.PutUint64(second[40:48], 5000)
	syncGPTCopiesAndChecksums(t, image)
	if _, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("overlapping GPT partitions accepted")
	}
}

func TestBuildPlanRejectsDuplicateGPTPartitionGUID(t *testing.T) {
	image, imageSize := testGPTImage(t, 3, false)
	primaryHeader := image[512:1024]
	entriesLBA := binary.LittleEndian.Uint64(primaryHeader[72:80])
	entrySize := binary.LittleEndian.Uint32(primaryHeader[84:88])
	first := image[entriesLBA*512 : entriesLBA*512+uint64(entrySize)]
	second := image[entriesLBA*512+uint64(entrySize) : entriesLBA*512+2*uint64(entrySize)]
	second[0] = 2
	copy(second[16:32], first[16:32])
	binary.LittleEndian.PutUint64(second[32:40], 6144)
	binary.LittleEndian.PutUint64(second[40:48], 8191)
	syncGPTCopiesAndChecksums(t, image)
	if _, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection()); err == nil {
		t.Fatal("duplicate GPT partition GUID accepted")
	}
}

func syncGPTCopiesAndChecksums(t *testing.T, image []byte) {
	t.Helper()
	primary := image[512:1024]
	backupLBA := binary.LittleEndian.Uint64(primary[32:40])
	entriesLBA := binary.LittleEndian.Uint64(primary[72:80])
	entries := binary.LittleEndian.Uint32(primary[80:84])
	entrySize := binary.LittleEndian.Uint32(primary[84:88])
	entriesBytes := uint64(entries) * uint64(entrySize)
	entrySectors := (entriesBytes + 511) / 512
	primaryTable := image[entriesLBA*512 : entriesLBA*512+entriesBytes]
	backupTable := image[(backupLBA-entrySectors)*512 : (backupLBA-entrySectors)*512+entriesBytes]
	copy(backupTable, primaryTable)
	entriesCRC := crc32.ChecksumIEEE(primaryTable)
	for _, header := range [][]byte{primary, image[backupLBA*512 : (backupLBA+1)*512]} {
		binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
		binary.LittleEndian.PutUint32(header[16:20], 0)
		headerSize := binary.LittleEndian.Uint32(header[12:16])
		binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:headerSize]))
	}
}
