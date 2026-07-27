package freedos

import (
	"encoding/binary"
	"strings"
	"testing"
)

const testMediaSize = 35 * 1024 * 1024

func TestNewMediaPlan(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatalf("plan test media: %v", err)
	}
	if plan.PartitionStartSector != 2048 || plan.PartitionSectorCount != 67584 || plan.SectorsPerCluster != 1 {
		t.Fatalf("unexpected media plan: %+v", plan)
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		t.Fatal(err)
	}
	if geometry.dataStartSector != 2048 || geometry.clusterCount != 65536 {
		t.Fatalf("unexpected FAT32 geometry: %+v", geometry)
	}
}

func TestMediaPlanRejectsAlteredContract(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*MediaPlan)
		want string
	}{
		{"sector size", func(value *MediaPlan) { value.LogicalSectorSize = 4096 }, "512-byte"},
		{"partition start", func(value *MediaPlan) { value.PartitionStartSector++ }, "1 MiB"},
		{"tail reservation", func(value *MediaPlan) { value.PartitionSectorCount-- }, "tail reservation"},
		{"cluster size", func(value *MediaPlan) { value.SectorsPerCluster = 2 }, "size table"},
		{"CHS geometry", func(value *MediaPlan) { value.Heads = 16 }, "CHS"},
		{"label", func(value *MediaPlan) { value.Label = "FreeDOS" }, "uppercase ASCII"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			altered := plan
			test.edit(&altered)
			if err := ValidateMediaPlan(altered); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestDefaultFreeDOSClusterSizeTable(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  uint64
	}{
		{63 * 1024 * 1024, 512},
		{64 * 1024 * 1024, 1024},
		{128 * 1024 * 1024, 2048},
		{256 * 1024 * 1024, 4096},
		{8 * 1024 * 1024 * 1024, 8192},
		{16 * 1024 * 1024 * 1024, 16384},
		{32 * 1024 * 1024 * 1024, 32768},
	}
	for _, test := range tests {
		got, err := defaultFreeDOSClusterBytes(test.bytes)
		if err != nil {
			t.Fatalf("cluster size for %d bytes: %v", test.bytes, err)
		}
		if got != test.want {
			t.Fatalf("cluster size for %d bytes = %d; want %d", test.bytes, got, test.want)
		}
	}
}

func TestVerifyMediaImage(t *testing.T) {
	image, plan := buildTestMedia(t)
	if err := VerifyMediaImage(image, plan); err != nil {
		t.Fatalf("verify valid media: %v", err)
	}
}

func TestVerifyMediaImageRejectsTampering(t *testing.T) {
	valid, plan := buildTestMedia(t)
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		t.Fatal(err)
	}
	partitionStart := int(plan.PartitionStartSector) * int(plan.LogicalSectorSize)
	fat1Start := partitionStart + int(geometry.reservedSectors)*int(plan.LogicalSectorSize)
	fat2Start := fat1Start + int(geometry.fatSectors)*int(plan.LogicalSectorSize)
	rootStart := partitionStart + int(geometry.dataStartSector)*int(plan.LogicalSectorSize)
	allocatedEnd := uint32(3) + clustersForSize(commandCOMSize, geometry.clusterBytes) + clustersForSize(kernelSYSSize, geometry.clusterBytes)
	tests := []struct {
		name string
		edit func([]byte)
		want string
	}{
		{"MBR CHS", func(image []byte) { image[447] ^= 1 }, "CHS"},
		{"backup BPB", func(image []byte) { image[partitionStart+6*512+0x1c] ^= 1 }, "BIOS parameter blocks differ"},
		{"FSInfo", func(image []byte) { image[partitionStart+512+488] ^= 1 }, "FSInfo"},
		{"FAT copies", func(image []byte) { image[fat2Start+3*4] ^= 1 }, "FAT copies differ"},
		{"command chain", func(image []byte) {
			putFATEntry(image[fat1Start:], 3, 0x0fffffff)
			putFATEntry(image[fat2Start:], 3, 0x0fffffff)
		}, "contiguous"},
		{"payload byte", func(image []byte) {
			commandStart := rootStart + int(geometry.clusterBytes)
			image[commandStart+17] ^= 1
		}, "file bytes"},
		{"orphan cluster", func(image []byte) {
			putFATEntry(image[fat1Start:], allocatedEnd, 0x0fffffff)
			putFATEntry(image[fat2Start:], allocatedEnd, 0x0fffffff)
		}, "orphan allocation"},
		{"extra root entry", func(image []byte) {
			copy(image[rootStart+96:rootStart+107], []byte("EXTRA   TXT"))
			image[rootStart+96+11] = 0x06
		}, "unexpected additional entry"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := append([]byte(nil), valid...)
			test.edit(image)
			if err := VerifyMediaImage(image, plan); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestLegacyCHSTranslation(t *testing.T) {
	if got, want := encodeLegacyCHS(2048, 255, 63), [3]byte{0x20, 0x21, 0x00}; got != want {
		t.Fatalf("start CHS = %x; want %x", got, want)
	}
	if got, want := encodeLegacyCHS(20_000_000, 255, 63), [3]byte{0xfe, 0xff, 0xff}; got != want {
		t.Fatalf("saturated CHS = %x; want %x", got, want)
	}
}

func buildTestMedia(t *testing.T) ([]byte, MediaPlan) {
	t.Helper()
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, int(plan.DiskSizeBytes))
	entry := image[446:462]
	entry[0] = 0x80
	startCHS := encodeLegacyCHS(uint64(plan.PartitionStartSector), plan.Heads, plan.SectorsPerTrack)
	endCHS := encodeLegacyCHS(uint64(plan.PartitionStartSector)+uint64(plan.PartitionSectorCount)-1, plan.Heads, plan.SectorsPerTrack)
	copy(entry[1:4], startCHS[:])
	entry[4] = 0x0c
	copy(entry[5:8], endCHS[:])
	binary.LittleEndian.PutUint32(entry[8:12], plan.PartitionStartSector)
	binary.LittleEndian.PutUint32(entry[12:16], plan.PartitionSectorCount)
	if err := ApplyRufusMBRCode(image[:512]); err != nil {
		t.Fatal(err)
	}

	partitionStart := int(plan.PartitionStartSector) * int(plan.LogicalSectorSize)
	partitionEnd := partitionStart + int(plan.PartitionSectorCount)*int(plan.LogicalSectorSize)
	partition := image[partitionStart:partitionEnd]
	label, _ := canonicalFATLabel(plan.Label)
	for _, base := range []int{0, fat32BackupSector * int(plan.LogicalSectorSize)} {
		boot := partition[base : base+int(plan.LogicalSectorSize)]
		binary.LittleEndian.PutUint16(boot[0x0b:0x0d], plan.LogicalSectorSize)
		boot[0x0d] = plan.SectorsPerCluster
		binary.LittleEndian.PutUint16(boot[0x0e:0x10], geometry.reservedSectors)
		boot[0x10] = freeDOSFATCount
		boot[0x15] = 0xf8
		binary.LittleEndian.PutUint16(boot[0x18:0x1a], plan.SectorsPerTrack)
		binary.LittleEndian.PutUint16(boot[0x1a:0x1c], plan.Heads)
		binary.LittleEndian.PutUint32(boot[0x1c:0x20], plan.PartitionStartSector)
		binary.LittleEndian.PutUint32(boot[0x20:0x24], plan.PartitionSectorCount)
		binary.LittleEndian.PutUint32(boot[0x24:0x28], geometry.fatSectors)
		binary.LittleEndian.PutUint32(boot[0x2c:0x30], freeDOSRootCluster)
		binary.LittleEndian.PutUint16(boot[0x30:0x32], freeDOSFSInfoSector)
		binary.LittleEndian.PutUint16(boot[0x32:0x34], fat32BackupSector)
		boot[0x40] = 0x80
		boot[0x42] = 0x29
		binary.LittleEndian.PutUint32(boot[0x43:0x47], 0x12345678)
		copy(boot[0x47:0x52], label[:])
		copy(boot[0x52:0x5a], []byte("FAT32   "))
		boot[510], boot[511] = 0x55, 0xaa
	}

	commandClusters := clustersForSize(uint32(len(payload.Command)), geometry.clusterBytes)
	kernelClusters := clustersForSize(uint32(len(payload.Kernel)), geometry.clusterBytes)
	allocatedEnd := uint32(3) + commandClusters + kernelClusters
	freeClusters := geometry.clusterCount - (1 + commandClusters + kernelClusters)
	for _, sector := range []int{freeDOSFSInfoSector, fat32BackupSector + freeDOSFSInfoSector} {
		fsInfo := partition[sector*int(plan.LogicalSectorSize) : (sector+1)*int(plan.LogicalSectorSize)]
		binary.LittleEndian.PutUint32(fsInfo[0:4], 0x41615252)
		binary.LittleEndian.PutUint32(fsInfo[484:488], 0x61417272)
		binary.LittleEndian.PutUint32(fsInfo[488:492], freeClusters)
		binary.LittleEndian.PutUint32(fsInfo[492:496], allocatedEnd)
		binary.LittleEndian.PutUint32(fsInfo[508:512], 0xaa550000)
	}

	fat1Start := int(geometry.reservedSectors) * int(plan.LogicalSectorSize)
	fatBytes := int(geometry.fatSectors) * int(plan.LogicalSectorSize)
	fat2Start := fat1Start + fatBytes
	for _, start := range []int{fat1Start, fat2Start} {
		fat := partition[start : start+fatBytes]
		putFATEntry(fat, 0, 0x0ffffff8)
		putFATEntry(fat, 1, 0x0fffffff)
		putFATEntry(fat, 2, 0x0fffffff)
		writeContiguousChain(fat, 3, commandClusters)
		writeContiguousChain(fat, 3+commandClusters, kernelClusters)
	}

	rootStart := int(geometry.dataStartSector) * int(plan.LogicalSectorSize)
	root := partition[rootStart : rootStart+int(geometry.clusterBytes)]
	copy(root[0:11], label[:])
	root[11] = 0x08
	writeDirectoryEntry(root[32:64], commandShortName, 0x06, 3, uint32(len(payload.Command)))
	writeDirectoryEntry(root[64:96], kernelShortName, 0x06, 3+commandClusters, uint32(len(payload.Kernel)))

	commandStart := rootStart + int(geometry.clusterBytes)
	copy(partition[commandStart:], payload.Command)
	kernelStart := commandStart + int(commandClusters)*int(geometry.clusterBytes)
	copy(partition[kernelStart:], payload.Kernel)

	if err := ApplyFreeDOSFAT32BootRegions(partition, int(plan.LogicalSectorSize)); err != nil {
		t.Fatal(err)
	}
	return image, plan
}

func writeDirectoryEntry(record []byte, name [11]byte, attributes byte, cluster, size uint32) {
	copy(record[:11], name[:])
	record[11] = attributes
	binary.LittleEndian.PutUint16(record[20:22], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(record[26:28], uint16(cluster))
	binary.LittleEndian.PutUint32(record[28:32], size)
}

func writeContiguousChain(fat []byte, first, count uint32) {
	for index := uint32(0); index < count; index++ {
		value := uint32(0x0fffffff)
		if index+1 < count {
			value = first + index + 1
		}
		putFATEntry(fat, first+index, value)
	}
}

func putFATEntry(fat []byte, cluster, value uint32) {
	offset := int(cluster) * 4
	binary.LittleEndian.PutUint32(fat[offset:offset+4], value)
}
