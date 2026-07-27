package freedos

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	MediaPlanSchema = 1

	freeDOSLogicalSectorSize       = 512
	freeDOSPartitionStartSector    = 2048
	freeDOSReservedTailSectors     = 2048
	freeDOSFATCount                = 2
	freeDOSFSInfoSector            = 1
	freeDOSRootCluster             = 2
	freeDOSDataAlignmentSectors    = 2048
	freeDOSMinimumClusterCount     = 65536
	freeDOSMaximumClusterCount     = 0x0fffffff
	freeDOSMaximumPartitionSectors = 0xfffffffe

	fat32EndOfChain = 0x0ffffff8
	fat32BadCluster = 0x0ffffff7
	fat32Mask       = 0x0fffffff
)

var (
	commandShortName = [11]byte{'C', 'O', 'M', 'M', 'A', 'N', 'D', ' ', 'C', 'O', 'M'}
	kernelShortName  = [11]byte{'K', 'E', 'R', 'N', 'E', 'L', ' ', ' ', 'S', 'Y', 'S'}
)

// MediaPlan is the deterministic, ordinary-file geometry contract for the
// narrow English-only FreeDOS checkpoint. It authorizes no device operation.
type MediaPlan struct {
	Schema               int    `json:"schema"`
	DiskSizeBytes        uint64 `json:"disk_size_bytes"`
	LogicalSectorSize    uint16 `json:"logical_sector_size"`
	PartitionStartSector uint32 `json:"partition_start_sector"`
	PartitionSectorCount uint32 `json:"partition_sector_count"`
	SectorsPerCluster    uint8  `json:"sectors_per_cluster"`
	SectorsPerTrack      uint16 `json:"sectors_per_track"`
	Heads                uint16 `json:"heads"`
	Label                string `json:"label"`
}

type mediaGeometry struct {
	reservedSectors uint16
	fatSectors      uint32
	dataStartSector uint32
	clusterCount    uint32
	clusterBytes    uint32
}

type mediaDirectoryEntry struct {
	name         [11]byte
	attributes   byte
	firstCluster uint32
	size         uint32
}

// NewMediaPlan returns the reviewed MBR/FAT32 geometry for an ordinary whole-
// disk image. The first and final MiB remain outside the single partition.
func NewMediaPlan(diskSizeBytes uint64, label string) (MediaPlan, error) {
	if diskSizeBytes%freeDOSLogicalSectorSize != 0 {
		return MediaPlan{}, errors.New("FreeDOS media size is not aligned to 512-byte logical sectors")
	}
	diskSectors := diskSizeBytes / freeDOSLogicalSectorSize
	if diskSectors > math.MaxUint32 {
		return MediaPlan{}, errors.New("FreeDOS MBR media exceeds the reviewed 32-bit LBA boundary")
	}
	if diskSectors <= freeDOSPartitionStartSector+freeDOSReservedTailSectors {
		return MediaPlan{}, errors.New("FreeDOS media is too small for the reviewed head and tail reservations")
	}
	partitionSectors := diskSectors - freeDOSPartitionStartSector - freeDOSReservedTailSectors
	if partitionSectors > freeDOSMaximumPartitionSectors {
		return MediaPlan{}, errors.New("FreeDOS FAT32 partition exceeds the reviewed sector-count boundary")
	}
	clusterBytes, err := defaultFreeDOSClusterBytes(partitionSectors * freeDOSLogicalSectorSize)
	if err != nil {
		return MediaPlan{}, err
	}
	plan := MediaPlan{
		Schema:               MediaPlanSchema,
		DiskSizeBytes:        diskSizeBytes,
		LogicalSectorSize:    freeDOSLogicalSectorSize,
		PartitionStartSector: freeDOSPartitionStartSector,
		PartitionSectorCount: uint32(partitionSectors),
		SectorsPerCluster:    uint8(clusterBytes / freeDOSLogicalSectorSize),
		SectorsPerTrack:      63,
		Heads:                255,
		Label:                label,
	}
	if err := ValidateMediaPlan(plan); err != nil {
		return MediaPlan{}, err
	}
	return plan, nil
}

// ValidateMediaPlan rejects altered geometry, labels, and size boundaries.
func ValidateMediaPlan(plan MediaPlan) error {
	if plan.Schema != MediaPlanSchema {
		return errors.New("unsupported FreeDOS media-plan schema")
	}
	if plan.LogicalSectorSize != freeDOSLogicalSectorSize {
		return errors.New("the reviewed FreeDOS media contract requires 512-byte logical sectors")
	}
	if plan.DiskSizeBytes == 0 || plan.DiskSizeBytes%uint64(plan.LogicalSectorSize) != 0 {
		return errors.New("invalid FreeDOS media size")
	}
	diskSectors := plan.DiskSizeBytes / uint64(plan.LogicalSectorSize)
	if diskSectors > math.MaxUint32 {
		return errors.New("FreeDOS media exceeds the MBR LBA boundary")
	}
	if plan.PartitionStartSector != freeDOSPartitionStartSector {
		return errors.New("FreeDOS partition does not begin at the reviewed 1 MiB boundary")
	}
	if plan.PartitionSectorCount == 0 || plan.PartitionSectorCount > freeDOSMaximumPartitionSectors {
		return errors.New("invalid FreeDOS partition sector count")
	}
	partitionEnd := uint64(plan.PartitionStartSector) + uint64(plan.PartitionSectorCount)
	if partitionEnd+freeDOSReservedTailSectors != diskSectors {
		return errors.New("FreeDOS partition does not preserve the reviewed 1 MiB tail reservation")
	}
	if plan.SectorsPerTrack != 63 || plan.Heads != 255 {
		return errors.New("FreeDOS CHS compatibility geometry was altered")
	}
	clusterBytes, err := defaultFreeDOSClusterBytes(uint64(plan.PartitionSectorCount) * uint64(plan.LogicalSectorSize))
	if err != nil {
		return err
	}
	if plan.SectorsPerCluster != uint8(clusterBytes/freeDOSLogicalSectorSize) {
		return errors.New("FreeDOS sectors-per-cluster does not match the reviewed size table")
	}
	if _, err := canonicalFATLabel(plan.Label); err != nil {
		return err
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		return err
	}
	if geometry.clusterCount < freeDOSMinimumClusterCount {
		return fmt.Errorf("FreeDOS FAT32 geometry has %d clusters; need at least %d", geometry.clusterCount, freeDOSMinimumClusterCount)
	}
	return nil
}

// VerifyMediaImage validates a complete ordinary-file disk image: MBR and CHS
// fields, both FreeDOS boot regions, FAT32 BPB and FSInfo copies, both FATs,
// root-directory records, exact allocation, and the pinned payload bytes.
func VerifyMediaImage(image []byte, plan MediaPlan) error {
	if err := ValidateMediaPlan(plan); err != nil {
		return err
	}
	if uint64(len(image)) != plan.DiskSizeBytes {
		return fmt.Errorf("FreeDOS image has %d bytes; expected %d", len(image), plan.DiskSizeBytes)
	}
	if err := VerifyRufusFreeDOSMBR(image[:mbrSectorSize]); err != nil {
		return fmt.Errorf("FreeDOS MBR: %w", err)
	}
	if err := verifyMediaMBR(image[:mbrSectorSize], plan); err != nil {
		return err
	}
	partitionStart := uint64(plan.PartitionStartSector) * uint64(plan.LogicalSectorSize)
	partitionSize := uint64(plan.PartitionSectorCount) * uint64(plan.LogicalSectorSize)
	partitionEnd := partitionStart + partitionSize
	if partitionEnd > uint64(len(image)) {
		return errors.New("FreeDOS partition extends beyond the image")
	}
	partition := image[int(partitionStart):int(partitionEnd)]
	if err := VerifyFreeDOSFAT32BootRegions(partition, int(plan.LogicalSectorSize)); err != nil {
		return fmt.Errorf("FreeDOS FAT32 boot regions: %w", err)
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		return err
	}
	if err := verifyMediaBPB(partition, plan, geometry); err != nil {
		return err
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		return fmt.Errorf("FreeDOS payload contract: %w", err)
	}
	return verifyMediaFilesystem(partition, plan, geometry, payload)
}

func defaultFreeDOSClusterBytes(partitionBytes uint64) (uint64, error) {
	switch {
	case partitionBytes < 32*1024*1024:
		return 0, errors.New("FreeDOS FAT32 partition is below the reviewed 32 MiB boundary")
	case partitionBytes < 64*1024*1024:
		return 512, nil
	case partitionBytes < 128*1024*1024:
		return 1024, nil
	case partitionBytes < 256*1024*1024:
		return 2048, nil
	case partitionBytes < 8*1024*1024*1024:
		return 4096, nil
	case partitionBytes < 16*1024*1024*1024:
		return 8192, nil
	case partitionBytes < 32*1024*1024*1024:
		return 16384, nil
	case partitionBytes < 2*1024*1024*1024*1024:
		return 32768, nil
	default:
		return 0, errors.New("FreeDOS FAT32 partition reaches the unsupported 2 TiB boundary")
	}
}

func expectedMediaGeometry(plan MediaPlan) (mediaGeometry, error) {
	total := uint64(plan.PartitionSectorCount)
	sectorsPerCluster := uint64(plan.SectorsPerCluster)
	if sectorsPerCluster == 0 {
		return mediaGeometry{}, errors.New("invalid zero sectors-per-cluster")
	}
	numerator := total + 2*sectorsPerCluster
	denominator := sectorsPerCluster*uint64(plan.LogicalSectorSize)/4 + freeDOSFATCount
	fatSectors := numerator/denominator + 1
	if fatSectors == 0 || fatSectors > math.MaxUint32 {
		return mediaGeometry{}, errors.New("invalid calculated FAT32 FAT size")
	}
	systemSectors := uint64(32) + freeDOSFATCount*fatSectors
	systemSectors = roundUp(systemSectors, freeDOSDataAlignmentSectors)
	if systemSectors >= total {
		return mediaGeometry{}, errors.New("FreeDOS FAT32 system area consumes the partition")
	}
	reserved := systemSectors - freeDOSFATCount*fatSectors
	if reserved <= fat32BackupSector || reserved > math.MaxUint16 {
		return mediaGeometry{}, errors.New("calculated FreeDOS FAT32 reserved-sector count is invalid")
	}
	clusterCount := (total - systemSectors) / sectorsPerCluster
	if clusterCount > freeDOSMaximumClusterCount {
		return mediaGeometry{}, errors.New("FreeDOS FAT32 geometry exceeds the 28-bit cluster boundary")
	}
	fatEntries := fatSectors * uint64(plan.LogicalSectorSize) / 4
	if fatEntries < clusterCount+2 {
		return mediaGeometry{}, errors.New("calculated FreeDOS FAT is too small for its clusters")
	}
	return mediaGeometry{
		reservedSectors: uint16(reserved),
		fatSectors:      uint32(fatSectors),
		dataStartSector: uint32(systemSectors),
		clusterCount:    uint32(clusterCount),
		clusterBytes:    uint32(plan.SectorsPerCluster) * uint32(plan.LogicalSectorSize),
	}, nil
}

func verifyMediaMBR(mbr []byte, plan MediaPlan) error {
	first := mbr[446:462]
	if binary.LittleEndian.Uint32(first[8:12]) != plan.PartitionStartSector ||
		binary.LittleEndian.Uint32(first[12:16]) != plan.PartitionSectorCount {
		return errors.New("FreeDOS MBR partition geometry does not match the reviewed plan")
	}
	wantStart := encodeLegacyCHS(uint64(plan.PartitionStartSector), plan.Heads, plan.SectorsPerTrack)
	wantEnd := encodeLegacyCHS(uint64(plan.PartitionStartSector)+uint64(plan.PartitionSectorCount)-1, plan.Heads, plan.SectorsPerTrack)
	if !bytes.Equal(first[1:4], wantStart[:]) || !bytes.Equal(first[5:8], wantEnd[:]) {
		return errors.New("FreeDOS MBR CHS fields do not match the reviewed LBA translation")
	}
	for index := 1; index < 4; index++ {
		entry := mbr[446+index*16 : 446+(index+1)*16]
		if !allZero(entry) {
			return errors.New("FreeDOS MBR contains an unexpected additional partition")
		}
	}
	return nil
}

func verifyMediaBPB(partition []byte, plan MediaPlan, geometry mediaGeometry) error {
	boot := partition[:plan.LogicalSectorSize]
	if binary.LittleEndian.Uint16(boot[0x0b:0x0d]) != plan.LogicalSectorSize || boot[0x0d] != plan.SectorsPerCluster {
		return errors.New("FreeDOS FAT32 sector or cluster size differs from the plan")
	}
	if binary.LittleEndian.Uint16(boot[0x0e:0x10]) != geometry.reservedSectors || boot[0x10] != freeDOSFATCount {
		return errors.New("FreeDOS FAT32 reserved-sector or FAT-count field differs from the plan")
	}
	if binary.LittleEndian.Uint16(boot[0x11:0x13]) != 0 || binary.LittleEndian.Uint16(boot[0x13:0x15]) != 0 ||
		boot[0x15] != 0xf8 || binary.LittleEndian.Uint16(boot[0x16:0x18]) != 0 {
		return errors.New("FreeDOS FAT32 legacy BPB fields are invalid")
	}
	if binary.LittleEndian.Uint16(boot[0x18:0x1a]) != plan.SectorsPerTrack || binary.LittleEndian.Uint16(boot[0x1a:0x1c]) != plan.Heads {
		return errors.New("FreeDOS FAT32 CHS compatibility fields differ from the plan")
	}
	if binary.LittleEndian.Uint32(boot[0x1c:0x20]) != plan.PartitionStartSector ||
		binary.LittleEndian.Uint32(boot[0x20:0x24]) != plan.PartitionSectorCount {
		return errors.New("FreeDOS FAT32 hidden-sector or total-sector field differs from the MBR")
	}
	if binary.LittleEndian.Uint32(boot[0x24:0x28]) != geometry.fatSectors ||
		binary.LittleEndian.Uint16(boot[0x28:0x2a]) != 0 ||
		binary.LittleEndian.Uint16(boot[0x2a:0x2c]) != 0 ||
		binary.LittleEndian.Uint32(boot[0x2c:0x30]) != freeDOSRootCluster ||
		binary.LittleEndian.Uint16(boot[0x30:0x32]) != freeDOSFSInfoSector ||
		binary.LittleEndian.Uint16(boot[0x32:0x34]) != fat32BackupSector {
		return errors.New("FreeDOS FAT32 extended BPB geometry is invalid")
	}
	if !allZero(boot[0x34:0x40]) || boot[0x40] != 0x80 || boot[0x41] != 0 || boot[0x42] != 0x29 {
		return errors.New("FreeDOS FAT32 drive or extended-signature fields are invalid")
	}
	label, _ := canonicalFATLabel(plan.Label)
	if !bytes.Equal(boot[0x47:0x52], label[:]) {
		return errors.New("FreeDOS FAT32 volume label differs from the plan")
	}
	if geometry.dataStartSector%freeDOSDataAlignmentSectors != 0 {
		return errors.New("FreeDOS FAT32 data region is not aligned to 1 MiB")
	}
	primaryFSInfo := partition[int(freeDOSFSInfoSector)*int(plan.LogicalSectorSize):]
	backupFSInfo := partition[int(fat32BackupSector+freeDOSFSInfoSector)*int(plan.LogicalSectorSize):]
	if err := verifyFSInfoSignatures(primaryFSInfo); err != nil {
		return fmt.Errorf("primary FreeDOS FAT32 FSInfo: %w", err)
	}
	if err := verifyFSInfoSignatures(backupFSInfo); err != nil {
		return fmt.Errorf("backup FreeDOS FAT32 FSInfo: %w", err)
	}
	if !bytes.Equal(primaryFSInfo[:plan.LogicalSectorSize], backupFSInfo[:plan.LogicalSectorSize]) {
		return errors.New("primary and backup FreeDOS FAT32 FSInfo sectors differ")
	}
	return nil
}

func verifyMediaFilesystem(partition []byte, plan MediaPlan, geometry mediaGeometry, payload MinimalPayload) error {
	sectorSize := uint64(plan.LogicalSectorSize)
	fatSizeBytes := uint64(geometry.fatSectors) * sectorSize
	fat1Start := uint64(geometry.reservedSectors) * sectorSize
	fat2Start := fat1Start + fatSizeBytes
	dataStart := uint64(geometry.dataStartSector) * sectorSize
	if dataStart > uint64(len(partition)) || fat2Start+fatSizeBytes > dataStart {
		return errors.New("FreeDOS FAT32 FAT or data offsets are outside the partition")
	}
	fat1 := partition[int(fat1Start):int(fat1Start+fatSizeBytes)]
	fat2 := partition[int(fat2Start):int(fat2Start+fatSizeBytes)]
	if !bytes.Equal(fat1, fat2) {
		return errors.New("FreeDOS FAT32 FAT copies differ")
	}
	if mediaFATEntry(fat1, 0) != 0x0ffffff8 || mediaFATEntry(fat1, 1) != 0x0fffffff || mediaFATEntry(fat1, freeDOSRootCluster) < fat32EndOfChain {
		return errors.New("FreeDOS FAT32 reserved or root FAT entries are invalid")
	}
	root, err := mediaCluster(partition, geometry, freeDOSRootCluster)
	if err != nil {
		return err
	}
	entries, err := parseMinimalRoot(root, plan)
	if err != nil {
		return err
	}
	commandEntry := entries[0]
	kernelEntry := entries[1]
	commandClusters := clustersForSize(commandEntry.size, geometry.clusterBytes)
	kernelClusters := clustersForSize(kernelEntry.size, geometry.clusterBytes)
	if commandEntry.firstCluster != 3 || kernelEntry.firstCluster != 3+commandClusters {
		return errors.New("FreeDOS payload clusters are not in the reviewed contiguous placement")
	}
	allocatedEnd := kernelEntry.firstCluster + kernelClusters
	if allocatedEnd > geometry.clusterCount+2 {
		return errors.New("FreeDOS payload allocation exceeds the FAT32 data region")
	}
	if err := verifyContiguousFile(partition, fat1, geometry, commandEntry, payload.Command); err != nil {
		return fmt.Errorf("COMMAND.COM: %w", err)
	}
	if err := verifyContiguousFile(partition, fat1, geometry, kernelEntry, payload.Kernel); err != nil {
		return fmt.Errorf("KERNEL.SYS: %w", err)
	}
	for cluster := allocatedEnd; cluster < geometry.clusterCount+2; cluster++ {
		if mediaFATEntry(fat1, cluster) != 0 {
			return fmt.Errorf("FreeDOS FAT32 contains orphan allocation at cluster %d", cluster)
		}
	}
	freeClusters := geometry.clusterCount - (1 + commandClusters + kernelClusters)
	nextFree := allocatedEnd
	primaryFSInfo := partition[int(freeDOSFSInfoSector)*int(plan.LogicalSectorSize):]
	if binary.LittleEndian.Uint32(primaryFSInfo[488:492]) != freeClusters || binary.LittleEndian.Uint32(primaryFSInfo[492:496]) != nextFree {
		return errors.New("FreeDOS FAT32 FSInfo allocation summary differs from the FAT")
	}
	return nil
}

func parseMinimalRoot(root []byte, plan MediaPlan) ([]mediaDirectoryEntry, error) {
	label, _ := canonicalFATLabel(plan.Label)
	var files []mediaDirectoryEntry
	liveIndex := 0
	for offset := 0; offset+32 <= len(root); offset += 32 {
		record := root[offset : offset+32]
		if record[0] == 0x00 {
			if !allZero(root[offset:]) {
				return nil, errors.New("FreeDOS root directory contains data after its terminator")
			}
			break
		}
		if record[0] == 0xe5 {
			return nil, errors.New("FreeDOS root directory contains a deleted entry")
		}
		attributes := record[11]
		if attributes == 0x0f {
			return nil, errors.New("FreeDOS root directory unexpectedly contains a long-filename entry")
		}
		var name [11]byte
		copy(name[:], record[:11])
		if liveIndex == 0 {
			if attributes != 0x08 || name != label || binary.LittleEndian.Uint32(record[28:32]) != 0 {
				return nil, errors.New("FreeDOS root volume-label entry is missing or altered")
			}
			liveIndex++
			continue
		}
		if attributes&0x18 != 0 || attributes&0x06 != 0x06 {
			return nil, errors.New("FreeDOS payload entry does not have the reviewed hidden/system attributes")
		}
		entry := mediaDirectoryEntry{
			name:         name,
			attributes:   attributes,
			firstCluster: uint32(binary.LittleEndian.Uint16(record[20:22]))<<16 | uint32(binary.LittleEndian.Uint16(record[26:28])),
			size:         binary.LittleEndian.Uint32(record[28:32]),
		}
		switch liveIndex {
		case 1:
			if entry.name != commandShortName || entry.size != commandCOMSize {
				return nil, errors.New("first FreeDOS payload entry is not the pinned COMMAND.COM")
			}
		case 2:
			if entry.name != kernelShortName || entry.size != kernelSYSSize {
				return nil, errors.New("second FreeDOS payload entry is not the pinned KERNEL.SYS")
			}
		default:
			return nil, errors.New("FreeDOS root directory contains an unexpected additional entry")
		}
		files = append(files, entry)
		liveIndex++
	}
	if liveIndex != 3 || len(files) != 2 {
		return nil, errors.New("FreeDOS root directory does not contain exactly the label and two payload files")
	}
	return files, nil
}

func verifyContiguousFile(partition, fat []byte, geometry mediaGeometry, entry mediaDirectoryEntry, expected []byte) error {
	if entry.size != uint32(len(expected)) {
		return errors.New("directory size does not match the pinned payload")
	}
	clusterCount := clustersForSize(entry.size, geometry.clusterBytes)
	if clusterCount == 0 || entry.firstCluster < 3 {
		return errors.New("invalid first cluster")
	}
	assembled := make([]byte, 0, uint64(clusterCount)*uint64(geometry.clusterBytes))
	for index := uint32(0); index < clusterCount; index++ {
		cluster := entry.firstCluster + index
		data, err := mediaCluster(partition, geometry, cluster)
		if err != nil {
			return err
		}
		assembled = append(assembled, data...)
		next := mediaFATEntry(fat, cluster)
		if index+1 < clusterCount {
			if next != cluster+1 {
				return fmt.Errorf("cluster %d does not point to the next contiguous cluster", cluster)
			}
		} else if next < fat32EndOfChain {
			return errors.New("final payload cluster is not end-of-chain")
		}
	}
	if !bytes.Equal(assembled[:len(expected)], expected) {
		return errors.New("file bytes do not match the pinned payload")
	}
	if !allZero(assembled[len(expected):]) {
		return errors.New("unused bytes in the final payload cluster are not zero")
	}
	return nil
}

func mediaCluster(partition []byte, geometry mediaGeometry, cluster uint32) ([]byte, error) {
	if cluster < 2 || cluster >= geometry.clusterCount+2 {
		return nil, fmt.Errorf("FreeDOS FAT32 cluster %d is outside the data region", cluster)
	}
	offset := uint64(geometry.dataStartSector)*freeDOSLogicalSectorSize + uint64(cluster-2)*uint64(geometry.clusterBytes)
	end := offset + uint64(geometry.clusterBytes)
	if end > uint64(len(partition)) {
		return nil, fmt.Errorf("FreeDOS FAT32 cluster %d extends beyond the partition", cluster)
	}
	return partition[int(offset):int(end)], nil
}

func mediaFATEntry(fat []byte, cluster uint32) uint32 {
	offset := uint64(cluster) * 4
	if offset+4 > uint64(len(fat)) {
		return fat32BadCluster
	}
	return binary.LittleEndian.Uint32(fat[int(offset):int(offset+4)]) & fat32Mask
}

func verifyFSInfoSignatures(sector []byte) error {
	if len(sector) < freeDOSLogicalSectorSize {
		return errors.New("sector is truncated")
	}
	if binary.LittleEndian.Uint32(sector[0:4]) != 0x41615252 ||
		binary.LittleEndian.Uint32(sector[484:488]) != 0x61417272 ||
		binary.LittleEndian.Uint32(sector[508:512]) != 0xaa550000 {
		return errors.New("signatures are invalid")
	}
	if !allZero(sector[4:484]) || !allZero(sector[496:508]) {
		return errors.New("reserved bytes are not zero")
	}
	return nil
}

func canonicalFATLabel(label string) ([11]byte, error) {
	var result [11]byte
	for index := range result {
		result[index] = ' '
	}
	if label == "" || len(label) > len(result) || strings.TrimSpace(label) != label {
		return result, errors.New("FreeDOS FAT32 label must contain 1 to 11 unpadded characters")
	}
	for index := 0; index < len(label); index++ {
		character := label[index]
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return result, errors.New("FreeDOS FAT32 label must use uppercase ASCII letters, digits, '-' or '_'")
		}
		result[index] = character
	}
	return result, nil
}

func encodeLegacyCHS(lba uint64, heads, sectorsPerTrack uint16) [3]byte {
	if heads == 0 || sectorsPerTrack == 0 {
		return [3]byte{}
	}
	cylinder := lba / (uint64(heads) * uint64(sectorsPerTrack))
	if cylinder > 1023 {
		return [3]byte{0xfe, 0xff, 0xff}
	}
	remainder := lba % (uint64(heads) * uint64(sectorsPerTrack))
	head := remainder / uint64(sectorsPerTrack)
	sector := remainder%uint64(sectorsPerTrack) + 1
	return [3]byte{
		byte(head),
		byte(sector&0x3f) | byte((cylinder>>2)&0xc0),
		byte(cylinder),
	}
}

func clustersForSize(size, clusterBytes uint32) uint32 {
	if size == 0 || clusterBytes == 0 {
		return 0
	}
	return (size + clusterBytes - 1) / clusterBytes
}

func roundUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
