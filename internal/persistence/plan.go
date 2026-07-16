package persistence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	sectorSize           = uint64(512)
	defaultAlignment     = uint64(1024 * 1024)
	minimumPartitionSize = uint64(1024 * 1024 * 1024)
	maxGPTEntriesBytes   = uint64(64 * 1024 * 1024)

	isoDescriptorSize  = uint64(2048)
	isoDescriptorStart = uint64(16) * isoDescriptorSize
	isoDescriptorLimit = 32
)

type TableKind string

const (
	TableMBR TableKind = "mbr"
	TableGPT TableKind = "gpt"
)

// Plan is a byte-accurate, non-destructive proposal for an append-only
// persistence partition. The writer tranche will consume this only after
// independently re-reading the image and target identities.
type Plan struct {
	Family                Family    `json:"family"`
	PartitionTable        TableKind `json:"partition_table"`
	PartitionNumber       int       `json:"partition_number"`
	StartBytes            uint64    `json:"start_bytes"`
	SizeBytes             uint64    `json:"size_bytes"`
	Filesystem            string    `json:"filesystem"`
	FilesystemLabel       string    `json:"filesystem_label"`
	BootParameter         string    `json:"boot_parameter"`
	PersistenceConfig     string    `json:"persistence_config,omitempty"`
	PatchPaths            []string  `json:"patch_paths,omitempty"`
	AlreadyEnabledPaths   []string  `json:"already_enabled_paths,omitempty"`
	RequiresGPTRelocation bool      `json:"requires_gpt_relocation,omitempty"`
}

// BuildPlan validates free partition-table capacity and target geometry. A
// requestedSize of zero uses all aligned space that remains on the target.
func BuildPlan(reader io.ReaderAt, imageSize, targetSize, requestedSize uint64, detection Detection) (Plan, error) {
	if reader == nil || imageSize < sectorSize {
		return Plan{}, errors.New("image is too small for a partition table")
	}
	if imageSize%sectorSize != 0 {
		return Plan{}, errors.New("image size is not aligned to 512-byte sectors")
	}
	if targetSize%sectorSize != 0 {
		return Plan{}, errors.New("target size is not aligned to 512-byte sectors")
	}
	if targetSize <= imageSize {
		return Plan{}, errors.New("target must be larger than the image")
	}
	if requestedSize != 0 && requestedSize%defaultAlignment != 0 {
		return Plan{}, fmt.Errorf("persistence size must be aligned to %d bytes", defaultAlignment)
	}
	if !detection.Ready() {
		return Plan{}, errors.New("media does not have a complete supported persistence contract")
	}
	layout, err := inspectTable(reader, imageSize)
	if err != nil {
		return Plan{}, err
	}
	start := alignUp(imageSize, defaultAlignment)
	if start < imageSize || targetSize <= start {
		return Plan{}, errors.New("target has no aligned space after the image")
	}
	limit := targetSize
	if layout.Kind == TableGPT {
		reserve := (layout.GPTEntrySectors + 1) * sectorSize
		if reserve >= limit {
			return Plan{}, errors.New("target is too small for relocated GPT backup data")
		}
		limit = alignDown(limit-reserve, defaultAlignment)
	} else {
		limit = alignDown(limit, defaultAlignment)
	}
	if limit <= start || limit-start < minimumPartitionSize {
		return Plan{}, fmt.Errorf("target needs at least %d bytes of aligned persistence space", minimumPartitionSize)
	}
	available := limit - start
	size := requestedSize
	if size == 0 {
		size = available
	} else {
		if size < minimumPartitionSize {
			return Plan{}, fmt.Errorf("persistence size must be at least %d bytes", minimumPartitionSize)
		}
		if size > available {
			return Plan{}, fmt.Errorf("requested persistence size %d exceeds available aligned space %d", size, available)
		}
	}
	if layout.Kind == TableMBR {
		startSector := start / sectorSize
		sizeSectors := size / sectorSize
		if startSector > math.MaxUint32 || sizeSectors == 0 || sizeSectors > math.MaxUint32 || startSector+sizeSectors > uint64(math.MaxUint32)+1 {
			return Plan{}, errors.New("planned persistence partition cannot be represented by a 32-bit MBR extent")
		}
	}
	return Plan{
		Family:                detection.Family,
		PartitionTable:        layout.Kind,
		PartitionNumber:       layout.FreeIndex + 1,
		StartBytes:            start,
		SizeBytes:             size,
		Filesystem:            detection.Filesystem,
		FilesystemLabel:       detection.FilesystemLabel,
		BootParameter:         detection.BootParameter,
		PersistenceConfig:     detection.PersistenceConfig,
		PatchPaths:            append([]string(nil), detection.PatchPaths...),
		AlreadyEnabledPaths:   append([]string(nil), detection.AlreadyEnabledPaths...),
		RequiresGPTRelocation: layout.Kind == TableGPT,
	}, nil
}

type tableLayout struct {
	Kind            TableKind
	FreeIndex       int
	GPTEntrySectors uint64
}

func inspectTable(reader io.ReaderAt, imageSize uint64) (tableLayout, error) {
	header := make([]byte, 1024)
	if _, err := reader.ReadAt(header, 0); err != nil && !errors.Is(err, io.EOF) {
		return tableLayout{}, fmt.Errorf("read image partition table: %w", err)
	}
	if header[510] != 0x55 || header[511] != 0xaa {
		return tableLayout{}, errors.New("persistence requires an MBR or GPT ISOHybrid image")
	}

	isoHybrid := hasISO9660PrimaryVolumeDescriptor(reader, imageSize)
	protective := false
	freeMBR := -1
	imageSectors := imageSize / sectorSize
	mbrExtents := make([]gptExtent, 0, 4)

	for index := 0; index < 4; index++ {
		entry := header[446+index*16 : 446+(index+1)*16]
		if allZero(entry) {
			if freeMBR < 0 {
				freeMBR = index
			}
			continue
		}
		if entry[0] != 0 && entry[0] != 0x80 {
			return tableLayout{}, fmt.Errorf("MBR partition %d has an invalid boot flag", index+1)
		}

		partitionType := entry[4]
		start := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		count := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		if partitionType == 0xee {
			if protective {
				return tableLayout{}, errors.New("MBR contains multiple GPT protective entries")
			}
			if start != 1 || count == 0 {
				return tableLayout{}, errors.New("GPT protective MBR entry has an invalid extent")
			}
			protective = true
			continue
		}

		// ISOHybrid producers such as xorriso may use occupied type-0 entries,
		// an ISO-covering extent beginning at LBA 0, and overlapping mappings for
		// embedded EFI/boot images. Those are metadata views of bytes inside the
		// ISO, not free partition slots. Permit them only when a real ISO9660 PVD
		// is present and every claimed sector remains inside the source image.
		if count == 0 || start+count < start || start+count > imageSectors || (!isoHybrid && (partitionType == 0 || start == 0)) {
			return tableLayout{}, fmt.Errorf(
				"MBR partition %d has an invalid extent (type=0x%02x start=%d sectors=%d image_sectors=%d)",
				index+1, partitionType, start, count, imageSectors,
			)
		}
		mbrExtents = append(mbrExtents, gptExtent{first: start, last: start + count - 1, index: index})
	}

	// Ordinary raw MBR images must remain non-overlapping. ISOHybrid tables are
	// intentionally allowed to contain overlapping views, but all of them were
	// already proven above to be bounded by the immutable source image. The new
	// persistence partition starts after that image, so it cannot overlap them.
	if !isoHybrid {
		sort.Slice(mbrExtents, func(i, j int) bool { return mbrExtents[i].first < mbrExtents[j].first })
		for index := 1; index < len(mbrExtents); index++ {
			if mbrExtents[index].first <= mbrExtents[index-1].last {
				return tableLayout{}, fmt.Errorf("MBR partitions %d and %d overlap", mbrExtents[index-1].index+1, mbrExtents[index].index+1)
			}
		}
	}

	gptSignature := string(header[512:520]) == "EFI PART"
	if protective != gptSignature {
		return tableLayout{}, errors.New("protective MBR and primary GPT header are inconsistent")
	}
	if protective {
		return inspectGPTTable(reader, imageSize, header[512:1024])
	}
	if freeMBR < 0 {
		return tableLayout{}, errors.New("MBR has no free primary partition entry for persistence")
	}
	return tableLayout{Kind: TableMBR, FreeIndex: freeMBR}, nil
}

func hasISO9660PrimaryVolumeDescriptor(reader io.ReaderAt, imageSize uint64) bool {
	if reader == nil || imageSize < isoDescriptorStart+isoDescriptorSize {
		return false
	}
	descriptor := make([]byte, isoDescriptorSize)
	for index := 0; index < isoDescriptorLimit; index++ {
		offset := isoDescriptorStart + uint64(index)*isoDescriptorSize
		if offset+isoDescriptorSize > imageSize {
			return false
		}
		if _, err := reader.ReadAt(descriptor, int64(offset)); err != nil {
			return false
		}
		if string(descriptor[1:6]) != "CD001" || descriptor[6] != 1 {
			continue
		}
		switch descriptor[0] {
		case 1:
			return true
		case 255:
			return false
		}
	}
	return false
}

type gptHeader struct {
	CurrentLBA  uint64
	BackupLBA   uint64
	FirstUsable uint64
	LastUsable  uint64
	DiskGUID    [16]byte
	EntriesLBA  uint64
	NumEntries  uint32
	EntrySize   uint32
	EntriesCRC  uint32
}

func inspectGPTTable(reader io.ReaderAt, imageSize uint64, primaryBytes []byte) (tableLayout, error) {
	if imageSize > math.MaxInt64 {
		return tableLayout{}, errors.New("GPT image is too large for safe inspection")
	}
	imageSectors := imageSize / sectorSize
	primary, err := parseGPTHeader(primaryBytes, "primary")
	if err != nil {
		return tableLayout{}, err
	}
	if primary.CurrentLBA != 1 || primary.BackupLBA != imageSectors-1 || primary.FirstUsable <= primary.CurrentLBA ||
		primary.LastUsable < primary.FirstUsable || primary.LastUsable >= primary.BackupLBA || primary.EntriesLBA < 2 {
		return tableLayout{}, errors.New("GPT geometry is not safe for append-only persistence planning")
	}
	entriesBytes := uint64(primary.NumEntries) * uint64(primary.EntrySize)
	entrySectors := (entriesBytes + sectorSize - 1) / sectorSize
	if entriesBytes == 0 || entriesBytes > maxGPTEntriesBytes || primary.EntriesLBA+entrySectors < primary.EntriesLBA ||
		primary.EntriesLBA+entrySectors > primary.FirstUsable {
		return tableLayout{}, errors.New("GPT primary entry table overlaps usable space or is outside the image")
	}
	if entrySectors >= primary.BackupLBA {
		return tableLayout{}, errors.New("GPT backup entry table is outside the image")
	}
	backupEntriesLBA := primary.BackupLBA - entrySectors
	if primary.LastUsable >= backupEntriesLBA {
		return tableLayout{}, errors.New("GPT backup entry table overlaps usable space")
	}
	primaryEntries, err := readAtExact(reader, primary.EntriesLBA*sectorSize, entriesBytes, "primary GPT entry table")
	if err != nil {
		return tableLayout{}, err
	}
	if crc32.ChecksumIEEE(primaryEntries) != primary.EntriesCRC {
		return tableLayout{}, errors.New("GPT primary entry-table CRC is invalid")
	}
	free, err := inspectGPTEntries(primaryEntries, primary)
	if err != nil {
		return tableLayout{}, err
	}
	if free < 0 {
		return tableLayout{}, errors.New("GPT has no free partition entry for persistence")
	}

	backupHeaderBytes, err := readAtExact(reader, primary.BackupLBA*sectorSize, sectorSize, "backup GPT header")
	if err != nil {
		return tableLayout{}, err
	}
	backup, err := parseGPTHeader(backupHeaderBytes, "backup")
	if err != nil {
		return tableLayout{}, err
	}
	if backup.CurrentLBA != primary.BackupLBA || backup.BackupLBA != primary.CurrentLBA ||
		backup.FirstUsable != primary.FirstUsable || backup.LastUsable != primary.LastUsable ||
		backup.DiskGUID != primary.DiskGUID || backup.EntriesLBA != backupEntriesLBA ||
		backup.NumEntries != primary.NumEntries || backup.EntrySize != primary.EntrySize || backup.EntriesCRC != primary.EntriesCRC {
		return tableLayout{}, errors.New("primary and backup GPT headers are inconsistent")
	}
	backupEntries, err := readAtExact(reader, backup.EntriesLBA*sectorSize, entriesBytes, "backup GPT entry table")
	if err != nil {
		return tableLayout{}, err
	}
	if crc32.ChecksumIEEE(backupEntries) != backup.EntriesCRC || !bytes.Equal(primaryEntries, backupEntries) {
		return tableLayout{}, errors.New("primary and backup GPT entry tables are inconsistent")
	}
	return tableLayout{Kind: TableGPT, FreeIndex: free, GPTEntrySectors: entrySectors}, nil
}

func parseGPTHeader(data []byte, role string) (gptHeader, error) {
	if len(data) < int(sectorSize) || string(data[:8]) != "EFI PART" {
		return gptHeader{}, fmt.Errorf("%s GPT header is missing", role)
	}
	headerSize := binary.LittleEndian.Uint32(data[12:16])
	if binary.LittleEndian.Uint32(data[8:12]) != 0x00010000 || headerSize < 92 || headerSize > uint32(sectorSize) ||
		binary.LittleEndian.Uint32(data[20:24]) != 0 {
		return gptHeader{}, fmt.Errorf("%s GPT header has invalid metadata", role)
	}
	storedCRC := binary.LittleEndian.Uint32(data[16:20])
	headerCopy := append([]byte(nil), data[:headerSize]...)
	binary.LittleEndian.PutUint32(headerCopy[16:20], 0)
	if crc32.ChecksumIEEE(headerCopy) != storedCRC {
		return gptHeader{}, fmt.Errorf("%s GPT header CRC is invalid", role)
	}
	var diskGUID [16]byte
	copy(diskGUID[:], data[56:72])
	numEntries := binary.LittleEndian.Uint32(data[80:84])
	entrySize := binary.LittleEndian.Uint32(data[84:88])
	entriesCRC := binary.LittleEndian.Uint32(data[88:92])
	if allZero(diskGUID[:]) || numEntries == 0 || numEntries > 1<<20 || entrySize < 128 || entrySize > 4096 || entrySize%8 != 0 {
		return gptHeader{}, fmt.Errorf("%s GPT header has unsafe entry-table metadata", role)
	}
	return gptHeader{
		CurrentLBA:  binary.LittleEndian.Uint64(data[24:32]),
		BackupLBA:   binary.LittleEndian.Uint64(data[32:40]),
		FirstUsable: binary.LittleEndian.Uint64(data[40:48]),
		LastUsable:  binary.LittleEndian.Uint64(data[48:56]),
		DiskGUID:    diskGUID,
		EntriesLBA:  binary.LittleEndian.Uint64(data[72:80]),
		NumEntries:  numEntries,
		EntrySize:   entrySize,
		EntriesCRC:  entriesCRC,
	}, nil
}

type gptExtent struct {
	first uint64
	last  uint64
	index int
}

func inspectGPTEntries(entries []byte, header gptHeader) (int, error) {
	free := -1
	extents := make([]gptExtent, 0)
	guids := make(map[[16]byte]int)
	for index := uint32(0); index < header.NumEntries; index++ {
		offset := uint64(index) * uint64(header.EntrySize)
		entry := entries[offset : offset+uint64(header.EntrySize)]
		if allZero(entry[:16]) {
			if !allZero(entry) {
				return -1, fmt.Errorf("unused GPT entry %d contains nonzero data", index+1)
			}
			if free < 0 {
				free = int(index)
			}
			continue
		}
		var uniqueGUID [16]byte
		copy(uniqueGUID[:], entry[16:32])
		if allZero(uniqueGUID[:]) {
			return -1, fmt.Errorf("GPT partition %d has an empty unique GUID", index+1)
		}
		if previous, exists := guids[uniqueGUID]; exists {
			return -1, fmt.Errorf("GPT partitions %d and %d use the same unique GUID", previous+1, index+1)
		}
		guids[uniqueGUID] = int(index)
		first := binary.LittleEndian.Uint64(entry[32:40])
		last := binary.LittleEndian.Uint64(entry[40:48])
		if first < header.FirstUsable || last < first || last > header.LastUsable {
			return -1, fmt.Errorf("GPT partition %d has an invalid extent", index+1)
		}
		extents = append(extents, gptExtent{first: first, last: last, index: int(index)})
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].first < extents[j].first })
	for index := 1; index < len(extents); index++ {
		if extents[index].first <= extents[index-1].last {
			return -1, fmt.Errorf("GPT partitions %d and %d overlap", extents[index-1].index+1, extents[index].index+1)
		}
	}
	return free, nil
}

func readAtExact(reader io.ReaderAt, offset, size uint64, description string) ([]byte, error) {
	if offset > math.MaxInt64 || size > math.MaxInt64 || offset+size < offset || offset+size > math.MaxInt64 {
		return nil, fmt.Errorf("%s is too large to inspect safely", description)
	}
	data := make([]byte, int(size))
	if _, err := reader.ReadAt(data, int64(offset)); err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}
	return data, nil
}

func alignUp(value, alignment uint64) uint64 {
	if alignment == 0 || value > ^uint64(0)-(alignment-1) {
		return ^uint64(0)
	}
	return (value + alignment - 1) / alignment * alignment
}

func alignDown(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return value / alignment * alignment
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

// ParseSize accepts an integer byte count or a binary K/M/G/T suffix. It is
// intentionally strict so CLI plans cannot silently reinterpret fractional or
// decimal-SI values.
func ParseSize(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return 0, nil
	}
	upper := strings.ToUpper(value)
	units := []struct {
		suffix string
		value  uint64
	}{
		{"TIB", 1 << 40}, {"TB", 1 << 40}, {"T", 1 << 40},
		{"GIB", 1 << 30}, {"GB", 1 << 30}, {"G", 1 << 30},
		{"MIB", 1 << 20}, {"MB", 1 << 20}, {"M", 1 << 20},
		{"KIB", 1 << 10}, {"KB", 1 << 10}, {"K", 1 << 10},
		{"B", 1},
	}
	multiplier := uint64(1)
	number := upper
	for _, unit := range units {
		if strings.HasSuffix(upper, unit.suffix) {
			number = strings.TrimSpace(upper[:len(upper)-len(unit.suffix)])
			multiplier = unit.value
			break
		}
	}
	if number == "" || strings.ContainsAny(number, ".+-") {
		return 0, fmt.Errorf("invalid size %q", value)
	}
	parsed, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", value, err)
	}
	if parsed != 0 && multiplier > ^uint64(0)/parsed {
		return 0, fmt.Errorf("size %q overflows uint64", value)
	}
	return parsed * multiplier, nil
}
