package freedos

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const freeDOSDeterministicVolumeID = 0x12345678

// BuildMediaImage constructs the reviewed FreeDOS whole-disk image entirely in
// memory, verifies the completed bytes against the media contract, and returns
// no device authority. Callers remain responsible for any separate safety-
// bound device execution layer.
func BuildMediaImage(plan MediaPlan) ([]byte, error) {
	if err := ValidateMediaPlan(plan); err != nil {
		return nil, err
	}
	maxInt := int(^uint(0) >> 1)
	if plan.DiskSizeBytes > uint64(maxInt) {
		return nil, errors.New("FreeDOS media is too large for this host address space")
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		return nil, err
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		return nil, fmt.Errorf("FreeDOS payload contract: %w", err)
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
	if err := ApplyRufusMBRCode(image[:mbrSectorSize]); err != nil {
		return nil, fmt.Errorf("apply FreeDOS MBR code: %w", err)
	}

	partitionStart := int(plan.PartitionStartSector) * int(plan.LogicalSectorSize)
	partitionEnd := partitionStart + int(plan.PartitionSectorCount)*int(plan.LogicalSectorSize)
	partition := image[partitionStart:partitionEnd]
	label, err := canonicalFATLabel(plan.Label)
	if err != nil {
		return nil, err
	}
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
		binary.LittleEndian.PutUint32(boot[0x43:0x47], freeDOSDeterministicVolumeID)
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
		putMediaFATEntry(fat, 0, 0x0ffffff8)
		putMediaFATEntry(fat, 1, 0x0fffffff)
		putMediaFATEntry(fat, 2, 0x0fffffff)
		writeMediaContiguousChain(fat, 3, commandClusters)
		writeMediaContiguousChain(fat, 3+commandClusters, kernelClusters)
	}

	rootStart := int(geometry.dataStartSector) * int(plan.LogicalSectorSize)
	root := partition[rootStart : rootStart+int(geometry.clusterBytes)]
	copy(root[0:11], label[:])
	root[11] = 0x08
	writeMediaDirectoryEntry(root[32:64], commandShortName, 0x06, 3, uint32(len(payload.Command)))
	writeMediaDirectoryEntry(root[64:96], kernelShortName, 0x06, 3+commandClusters, uint32(len(payload.Kernel)))

	commandStart := rootStart + int(geometry.clusterBytes)
	copy(partition[commandStart:], payload.Command)
	kernelStart := commandStart + int(commandClusters)*int(geometry.clusterBytes)
	copy(partition[kernelStart:], payload.Kernel)

	if err := ApplyFreeDOSFAT32BootRegions(partition, int(plan.LogicalSectorSize)); err != nil {
		return nil, fmt.Errorf("apply FreeDOS FAT32 boot regions: %w", err)
	}
	if err := VerifyMediaImage(image, plan); err != nil {
		return nil, fmt.Errorf("verify constructed FreeDOS media: %w", err)
	}
	return image, nil
}

func writeMediaDirectoryEntry(record []byte, name [11]byte, attributes byte, cluster, size uint32) {
	copy(record[:11], name[:])
	record[11] = attributes
	binary.LittleEndian.PutUint16(record[20:22], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(record[26:28], uint16(cluster))
	binary.LittleEndian.PutUint32(record[28:32], size)
}

func writeMediaContiguousChain(fat []byte, first, count uint32) {
	for index := uint32(0); index < count; index++ {
		value := uint32(0x0fffffff)
		if index+1 < count {
			value = first + index + 1
		}
		putMediaFATEntry(fat, first+index, value)
	}
}

func putMediaFATEntry(fat []byte, cluster, value uint32) {
	offset := int(cluster) * 4
	binary.LittleEndian.PutUint32(fat[offset:offset+4], value)
}
