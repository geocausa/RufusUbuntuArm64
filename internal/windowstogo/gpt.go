//go:build linux

package windowstogo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

const (
	gptEntryCount = uint32(128)
	gptEntrySize  = uint32(128)
	gptHeaderSize = uint32(92)
)

type GPTPartition struct {
	Number      int    `json:"number"`
	TypeGUID    GUID   `json:"type_guid"`
	UniqueGUID  GUID   `json:"unique_guid"`
	FirstLBA    uint64 `json:"first_lba"`
	LastLBA     uint64 `json:"last_lba"`
	Attributes  uint64 `json:"attributes"`
	Name        string `json:"name"`
	Filesystem  string `json:"filesystem"`
	VolumeLabel string `json:"volume_label"`
}

type GPTLayout struct {
	SectorSize        uint64         `json:"sector_size"`
	TotalSectors      uint64         `json:"total_sectors"`
	DiskGUID          GUID           `json:"disk_guid"`
	Partitions        []GPTPartition `json:"partitions"`
	PrimaryHeaderLBA  uint64         `json:"primary_header_lba"`
	PrimaryEntriesLBA uint64         `json:"primary_entries_lba"`
	BackupEntriesLBA  uint64         `json:"backup_entries_lba"`
	BackupHeaderLBA   uint64         `json:"backup_header_lba"`
	FirstUsableLBA    uint64         `json:"first_usable_lba"`
	LastUsableLBA     uint64         `json:"last_usable_lba"`
	ProtectiveMBR     []byte         `json:"-"`
	PrimaryEntries    []byte         `json:"-"`
	PrimaryHeader     []byte         `json:"-"`
	BackupEntries     []byte         `json:"-"`
	BackupHeader      []byte         `json:"-"`
}

func BuildGPT(plan Plan, random io.Reader) (GPTLayout, error) {
	if err := ValidatePlan(plan); err != nil {
		return GPTLayout{}, err
	}
	if plan.TargetSizeBytes%plan.LogicalSectorSize != 0 {
		return GPTLayout{}, errors.New("target capacity is not an exact logical-sector multiple")
	}
	totalSectors := plan.TargetSizeBytes / plan.LogicalSectorSize
	entriesBytes := uint64(gptEntryCount) * uint64(gptEntrySize)
	entrySectors := (entriesBytes + plan.LogicalSectorSize - 1) / plan.LogicalSectorSize
	if totalSectors <= 2*entrySectors+2 {
		return GPTLayout{}, errors.New("target is too small for primary and backup GPT metadata")
	}
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalSectors - 1
	backupEntriesLBA := backupHeaderLBA - entrySectors
	firstUsableLBA := primaryEntriesLBA + entrySectors
	lastUsableLBA := backupEntriesLBA - 1

	diskGUID, err := RandomGUID(random)
	if err != nil {
		return GPTLayout{}, err
	}
	espGUID, err := RandomGUID(random)
	if err != nil {
		return GPTLayout{}, err
	}
	osGUID, err := RandomGUID(random)
	if err != nil {
		return GPTLayout{}, err
	}
	espType, err := ParseGUID(efiSystemPartitionGUID)
	if err != nil {
		return GPTLayout{}, err
	}
	osType, err := ParseGUID(basicDataPartitionGUID)
	if err != nil {
		return GPTLayout{}, err
	}
	partitions := []GPTPartition{
		partitionFromPlan(plan.ESP, espType, espGUID, plan.LogicalSectorSize),
		partitionFromPlan(plan.OS, osType, osGUID, plan.LogicalSectorSize),
	}
	for _, partition := range partitions {
		if partition.FirstLBA < firstUsableLBA || partition.LastLBA > lastUsableLBA || partition.FirstLBA > partition.LastLBA {
			return GPTLayout{}, fmt.Errorf("partition %d is outside usable GPT geometry", partition.Number)
		}
	}
	if partitions[0].LastLBA >= partitions[1].FirstLBA {
		return GPTLayout{}, errors.New("windows To Go GPT partitions overlap")
	}

	entries := make([]byte, entrySectors*plan.LogicalSectorSize)
	for index, partition := range partitions {
		entry, err := encodeGPTEntry(partition)
		if err != nil {
			return GPTLayout{}, err
		}
		copy(entries[index*int(gptEntrySize):], entry)
	}
	entriesCRC := crc32.ChecksumIEEE(entries[:entriesBytes])
	primaryHeader, err := encodeGPTHeader(plan.LogicalSectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	if err != nil {
		return GPTLayout{}, err
	}
	backupHeader, err := encodeGPTHeader(plan.LogicalSectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	if err != nil {
		return GPTLayout{}, err
	}
	mbr, err := protectiveMBR(plan.LogicalSectorSize, totalSectors)
	if err != nil {
		return GPTLayout{}, err
	}
	layout := GPTLayout{
		SectorSize: plan.LogicalSectorSize, TotalSectors: totalSectors, DiskGUID: diskGUID,
		Partitions: partitions, PrimaryHeaderLBA: 1, PrimaryEntriesLBA: primaryEntriesLBA,
		BackupEntriesLBA: backupEntriesLBA, BackupHeaderLBA: backupHeaderLBA,
		FirstUsableLBA: firstUsableLBA, LastUsableLBA: lastUsableLBA,
		ProtectiveMBR: mbr, PrimaryEntries: entries, PrimaryHeader: primaryHeader,
		BackupEntries: append([]byte(nil), entries...), BackupHeader: backupHeader,
	}
	if err := ValidateGPT(layout, plan); err != nil {
		return GPTLayout{}, err
	}
	return layout, nil
}

func partitionFromPlan(partition Partition, typeGUID, uniqueGUID GUID, sectorSize uint64) GPTPartition {
	return GPTPartition{
		Number: partition.Number, TypeGUID: typeGUID, UniqueGUID: uniqueGUID,
		FirstLBA:   partition.StartBytes / sectorSize,
		LastLBA:    (partition.StartBytes+partition.SizeBytes)/sectorSize - 1,
		Attributes: partition.Attributes, Name: partition.GPTName,
		Filesystem: partition.Filesystem, VolumeLabel: partition.Label,
	}
}

func encodeGPTEntry(partition GPTPartition) ([]byte, error) {
	if partition.Number < 1 || partition.Number > int(gptEntryCount) {
		return nil, fmt.Errorf("invalid GPT partition number %d", partition.Number)
	}
	entry := make([]byte, gptEntrySize)
	typeBytes := partition.TypeGUID.DiskBytes()
	uniqueBytes := partition.UniqueGUID.DiskBytes()
	copy(entry[0:16], typeBytes[:])
	copy(entry[16:32], uniqueBytes[:])
	binary.LittleEndian.PutUint64(entry[32:40], partition.FirstLBA)
	binary.LittleEndian.PutUint64(entry[40:48], partition.LastLBA)
	binary.LittleEndian.PutUint64(entry[48:56], partition.Attributes)
	name := utf16.Encode([]rune(partition.Name))
	if len(name) > 36 {
		return nil, fmt.Errorf("GPT partition name %q exceeds 36 UTF-16 code units", partition.Name)
	}
	for index, unit := range name {
		binary.LittleEndian.PutUint16(entry[56+index*2:58+index*2], unit)
	}
	return entry, nil
}

func encodeGPTHeader(sectorSize, currentLBA, backupLBA, firstUsable, lastUsable uint64, diskGUID GUID, entriesLBA uint64, entriesCRC uint32) ([]byte, error) {
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, errors.New("unsupported GPT sector size")
	}
	header := make([]byte, sectorSize)
	copy(header[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], gptHeaderSize)
	binary.LittleEndian.PutUint64(header[24:32], currentLBA)
	binary.LittleEndian.PutUint64(header[32:40], backupLBA)
	binary.LittleEndian.PutUint64(header[40:48], firstUsable)
	binary.LittleEndian.PutUint64(header[48:56], lastUsable)
	guidBytes := diskGUID.DiskBytes()
	copy(header[56:72], guidBytes[:])
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], gptEntrySize)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:gptHeaderSize]))
	return header, nil
}

func protectiveMBR(sectorSize, totalSectors uint64) ([]byte, error) {
	if sectorSize < 512 || totalSectors < 2 {
		return nil, errors.New("invalid protective MBR geometry")
	}
	mbr := make([]byte, sectorSize)
	entry := mbr[446:462]
	entry[0] = 0x00
	entry[1], entry[2], entry[3] = 0x00, 0x02, 0x00
	entry[4] = 0xee
	entry[5], entry[6], entry[7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	length := totalSectors - 1
	if length > uint64(^uint32(0)) {
		length = uint64(^uint32(0))
	}
	binary.LittleEndian.PutUint32(entry[12:16], uint32(length))
	mbr[510], mbr[511] = 0x55, 0xaa
	return mbr, nil
}

func ValidateGPT(layout GPTLayout, plan Plan) error {
	if len(layout.Partitions) != 2 || len(layout.ProtectiveMBR) != int(layout.SectorSize) ||
		len(layout.PrimaryHeader) != int(layout.SectorSize) || len(layout.BackupHeader) != int(layout.SectorSize) ||
		!bytes.Equal(layout.PrimaryEntries, layout.BackupEntries) {
		return errors.New("incomplete Windows To Go GPT image")
	}
	if layout.TotalSectors != plan.TargetSizeBytes/plan.LogicalSectorSize || layout.SectorSize != plan.LogicalSectorSize {
		return errors.New("the GPT image does not match target geometry")
	}
	if layout.ProtectiveMBR[510] != 0x55 || layout.ProtectiveMBR[511] != 0xaa || layout.ProtectiveMBR[450] != 0xee {
		return errors.New("protective MBR is invalid")
	}
	for _, header := range [][]byte{layout.PrimaryHeader, layout.BackupHeader} {
		if string(header[:8]) != "EFI PART" || binary.LittleEndian.Uint32(header[12:16]) != gptHeaderSize {
			return errors.New("the GPT header signature or size is invalid")
		}
		storedCRC := binary.LittleEndian.Uint32(header[16:20])
		copyHeader := append([]byte(nil), header[:gptHeaderSize]...)
		binary.LittleEndian.PutUint32(copyHeader[16:20], 0)
		if crc32.ChecksumIEEE(copyHeader) != storedCRC {
			return errors.New("the GPT header CRC is invalid")
		}
		entriesLength := int(binary.LittleEndian.Uint32(header[80:84]) * binary.LittleEndian.Uint32(header[84:88]))
		if entriesLength > len(layout.PrimaryEntries) || crc32.ChecksumIEEE(layout.PrimaryEntries[:entriesLength]) != binary.LittleEndian.Uint32(header[88:92]) {
			return errors.New("the GPT entry-table CRC is invalid")
		}
	}
	if layout.Partitions[0].TypeGUID.String() != stringsLowerGUID(efiSystemPartitionGUID) ||
		layout.Partitions[1].TypeGUID.String() != stringsLowerGUID(basicDataPartitionGUID) ||
		layout.Partitions[1].Attributes != noDefaultDriveLetter {
		return errors.New("the GPT partition types or attributes are invalid")
	}
	return nil
}

func stringsLowerGUID(value string) string {
	var result []byte
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'F' {
			character += 'a' - 'A'
		}
		result = append(result, character)
	}
	return string(result)
}
