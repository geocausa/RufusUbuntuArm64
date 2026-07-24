package ffu

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
)

const (
	maxPlanDescriptorCount = uint32(1 << 18)
	maxPlanLocationCount   = uint64(1 << 20)
	maxPlanTableBytes      = uint64(256 << 20)

	diskAccessBegin = uint32(0)
	diskAccessEnd   = uint32(2)
)

// PayloadTableRange describes a block range in the sequential FFU payload.
type PayloadTableRange struct {
	BlockIndex uint32 `json:"block_index"`
	BlockCount uint32 `json:"block_count"`
	BlockEnd   uint64 `json:"block_end"`
}

// ValidationDescriptor describes one read-before-write comparison entry. The
// comparison bytes are represented by a digest rather than retained in memory.
type ValidationDescriptor struct {
	Index             uint32 `json:"index"`
	TableOffset       uint64 `json:"table_offset"`
	SectorIndex       uint32 `json:"sector_index"`
	SectorOffset      uint32 `json:"sector_offset"`
	ByteCount         uint32 `json:"byte_count"`
	CompareDataOffset uint64 `json:"compare_data_offset"`
	CompareDataSHA256 string `json:"compare_data_sha256"`
}

// DiskLocation is a destination expression anchored at the beginning or end of
// the future target. It is not converted to a byte offset until target size is
// identity-bound by a later planner.
type DiskLocation struct {
	Index        uint32 `json:"index"`
	AccessMethod uint32 `json:"access_method"`
	Anchor       string `json:"anchor"`
	BlockIndex   uint32 `json:"block_index"`
	BlockEnd     uint64 `json:"block_end"`
}

// WriteDescriptor maps one sequential payload extent to one or more target
// location expressions. Multiple locations reuse the same payload bytes.
type WriteDescriptor struct {
	Index         uint32         `json:"index"`
	TableOffset   uint64         `json:"table_offset"`
	LocationCount uint32         `json:"location_count"`
	BlockCount    uint32         `json:"block_count"`
	PayloadOffset uint64         `json:"payload_offset"`
	PayloadLength uint64         `json:"payload_length"`
	Locations     []DiskLocation `json:"locations"`
}

// DestinationOverlap records an overlap that is independent of target size
// because both expressions use the same anchor.
type DestinationOverlap struct {
	Anchor                string `json:"anchor"`
	FirstDescriptorIndex  uint32 `json:"first_descriptor_index"`
	FirstLocationIndex    uint32 `json:"first_location_index"`
	SecondDescriptorIndex uint32 `json:"second_descriptor_index"`
	SecondLocationIndex   uint32 `json:"second_location_index"`
	OverlapStartBlock     uint64 `json:"overlap_start_block"`
	OverlapEndBlock       uint64 `json:"overlap_end_block"`
}

// DescriptorPlan is a deterministic read-only plan for the legacy single-store
// header layout. It is not an execution authorization.
type DescriptorPlan struct {
	Schema                     int                    `json:"schema"`
	StoreMajorVersion          uint16                 `json:"store_major_version"`
	StoreMinorVersion          uint16                 `json:"store_minor_version"`
	SourceFileSize             uint64                 `json:"source_file_size"`
	ChunkSizeBytes             uint64                 `json:"chunk_size_bytes"`
	BlockSizeBytes             uint64                 `json:"block_size_bytes"`
	ValidationDescriptorOffset uint64                 `json:"validation_descriptor_offset"`
	WriteDescriptorOffset      uint64                 `json:"write_descriptor_offset"`
	WriteDescriptorEnd         uint64                 `json:"write_descriptor_end"`
	PayloadOffset              uint64                 `json:"payload_offset"`
	PayloadLength              uint64                 `json:"payload_length"`
	PayloadEnd                 uint64                 `json:"payload_end"`
	PayloadFileBytes           uint64                 `json:"payload_file_bytes"`
	TrailingFileBytes          uint64                 `json:"trailing_file_bytes"`
	TotalPayloadBlocks         uint64                 `json:"total_payload_blocks"`
	BeginningExtentBlocks      uint64                 `json:"beginning_extent_blocks"`
	EndingExtentBlocks         uint64                 `json:"ending_extent_blocks"`
	MinimumTargetBlocks        uint64                 `json:"minimum_target_blocks"`
	MinimumTargetBytes         uint64                 `json:"minimum_target_bytes"`
	InitialTable               PayloadTableRange      `json:"initial_table"`
	FlashOnlyTable             PayloadTableRange      `json:"flash_only_table"`
	FinalTable                 PayloadTableRange      `json:"final_table"`
	ValidationDescriptors      []ValidationDescriptor `json:"validation_descriptors"`
	WriteDescriptors           []WriteDescriptor      `json:"write_descriptors"`
	DestinationOverlaps        []DestinationOverlap   `json:"destination_overlaps"`
	HasDestinationOverlap      bool                   `json:"has_destination_overlap"`
	TargetSizeBindingRequired  bool                   `json:"target_size_binding_required"`
	IntegrityAuthenticated     bool                   `json:"integrity_authenticated"`
	ExecutionSupported         bool                   `json:"execution_supported"`
	PlanSHA256                 string                 `json:"plan_sha256"`
	Limitations                []string               `json:"limitations"`
}

// PlanSingleStoreV1 re-inspects the source and resolves the descriptor and
// payload layout only for store-header version 1.0. Newer layouts remain hard
// refusals because they contain additional fixed or variable store metadata.
func PlanSingleStoreV1(reader io.ReaderAt, size uint64) (Inspection, DescriptorPlan, error) {
	inspection, err := Inspect(reader, size)
	if err != nil {
		return Inspection{}, DescriptorPlan{}, err
	}
	store := inspection.Store
	if store.MajorVersion != 1 || store.MinorVersion != 0 {
		return inspection, DescriptorPlan{}, fmt.Errorf("unsupported FFU store-header version %d.%d: single-store planning requires 1.0", store.MajorVersion, store.MinorVersion)
	}
	if store.WriteDescriptorCount > maxPlanDescriptorCount || store.ValidateDescriptorCount > maxPlanDescriptorCount {
		return inspection, DescriptorPlan{}, fmt.Errorf("FFU descriptor count exceeds read-only planning limit %d", maxPlanDescriptorCount)
	}
	if uint64(store.WriteDescriptorLength) > maxPlanTableBytes || uint64(store.ValidateDescriptorLength) > maxPlanTableBytes {
		return inspection, DescriptorPlan{}, fmt.Errorf("FFU descriptor table exceeds read-only planning limit %d bytes", maxPlanTableBytes)
	}

	validationOffset := inspection.StoreCommonEndOffset
	writeOffset, err := checkedAdd(validationOffset, uint64(store.ValidateDescriptorLength))
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU validation descriptor boundary overflows")
	}
	writeEnd, err := checkedAdd(writeOffset, uint64(store.WriteDescriptorLength))
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU write descriptor boundary overflows")
	}
	payloadOffset, err := alignUp(writeEnd, inspection.Security.ChunkSizeBytes)
	if err != nil {
		return inspection, DescriptorPlan{}, fmt.Errorf("align FFU payload: %w", err)
	}
	if payloadOffset > size {
		return inspection, DescriptorPlan{}, fmt.Errorf("FFU payload starts at %d beyond file size %d", payloadOffset, size)
	}

	validations, err := parseValidationDescriptors(reader, size, validationOffset, writeOffset, store.ValidateDescriptorCount)
	if err != nil {
		return inspection, DescriptorPlan{}, err
	}
	writes, totalBlocks, beginningBlocks, endingBlocks, intervals, err := parseWriteDescriptors(
		reader,
		size,
		writeOffset,
		writeEnd,
		payloadOffset,
		store.WriteDescriptorCount,
		uint64(store.BlockSizeBytes),
	)
	if err != nil {
		return inspection, DescriptorPlan{}, err
	}

	payloadLength, err := checkedMul(totalBlocks, uint64(store.BlockSizeBytes))
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU payload length overflows")
	}
	payloadEnd, err := checkedAdd(payloadOffset, payloadLength)
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU payload end overflows")
	}
	if payloadEnd > size {
		return inspection, DescriptorPlan{}, fmt.Errorf("FFU payload requires end byte %d beyond file size %d", payloadEnd, size)
	}
	minimumTargetBlocks, err := checkedAdd(beginningBlocks, endingBlocks)
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU minimum target block count overflows")
	}
	minimumTargetBytes, err := checkedMul(minimumTargetBlocks, uint64(store.BlockSizeBytes))
	if err != nil {
		return inspection, DescriptorPlan{}, errors.New("FFU minimum target byte count overflows")
	}

	initial := payloadRange(store.InitialTableBlockIndex, store.InitialTableBlockCount, store.InitialTableBlockEnd)
	flashOnly := payloadRange(store.FlashOnlyTableBlockIndex, store.FlashOnlyTableBlockCount, store.FlashOnlyTableBlockEnd)
	final := payloadRange(store.FinalTableBlockIndex, store.FinalTableBlockCount, store.FinalTableBlockEnd)
	tables := []struct {
		name       string
		rangeValue PayloadTableRange
	}{
		{name: "initial", rangeValue: initial},
		{name: "flash-only", rangeValue: flashOnly},
		{name: "final", rangeValue: final},
	}
	for _, item := range tables {
		table := item.rangeValue
		if table.BlockCount != 0 && table.BlockEnd > totalBlocks {
			return inspection, DescriptorPlan{}, fmt.Errorf("FFU %s GPT table payload range [%d,%d) exceeds %d payload blocks", item.name, table.BlockIndex, table.BlockEnd, totalBlocks)
		}
	}

	overlaps := detectSameAnchorOverlaps(intervals)
	plan := DescriptorPlan{
		Schema:                     1,
		StoreMajorVersion:          store.MajorVersion,
		StoreMinorVersion:          store.MinorVersion,
		SourceFileSize:             size,
		ChunkSizeBytes:             inspection.Security.ChunkSizeBytes,
		BlockSizeBytes:             uint64(store.BlockSizeBytes),
		ValidationDescriptorOffset: validationOffset,
		WriteDescriptorOffset:      writeOffset,
		WriteDescriptorEnd:         writeEnd,
		PayloadOffset:              payloadOffset,
		PayloadLength:              payloadLength,
		PayloadEnd:                 payloadEnd,
		PayloadFileBytes:           size - payloadOffset,
		TrailingFileBytes:          size - payloadEnd,
		TotalPayloadBlocks:         totalBlocks,
		BeginningExtentBlocks:      beginningBlocks,
		EndingExtentBlocks:         endingBlocks,
		MinimumTargetBlocks:        minimumTargetBlocks,
		MinimumTargetBytes:         minimumTargetBytes,
		InitialTable:               initial,
		FlashOnlyTable:             flashOnly,
		FinalTable:                 final,
		ValidationDescriptors:      validations,
		WriteDescriptors:           writes,
		DestinationOverlaps:        overlaps,
		HasDestinationOverlap:      len(overlaps) != 0,
		TargetSizeBindingRequired:  true,
		IntegrityAuthenticated:     false,
		ExecutionSupported:         false,
		Limitations: []string{
			"only store-header version 1.0 is resolved",
			"the signed catalog and chunk hash table are not yet authenticated",
			"end-anchored locations require an identity-bound target size",
			"cross-anchor destination overlap requires target-specific validation",
			"trailing file bytes are reported but not interpreted",
			"no target executor exists and no device can be written",
		},
	}
	plan.PlanSHA256 = descriptorPlanDigest(plan)
	return inspection, plan, nil
}

func parseValidationDescriptors(reader io.ReaderAt, size, start, end uint64, count uint32) ([]ValidationDescriptor, error) {
	cursor := start
	result := make([]ValidationDescriptor, 0, count)
	for index := uint32(0); index < count; index++ {
		header, err := readRegion(reader, size, cursor, 12, fmt.Sprintf("validation descriptor %d", index))
		if err != nil {
			return nil, err
		}
		byteCount := binary.LittleEndian.Uint32(header[8:12])
		if byteCount == 0 {
			return nil, fmt.Errorf("FFU validation descriptor %d has zero comparison bytes", index)
		}
		compareOffset, err := checkedAdd(cursor, 12)
		if err != nil {
			return nil, fmt.Errorf("FFU validation descriptor %d data offset overflows", index)
		}
		next, err := checkedAdd(compareOffset, uint64(byteCount))
		if err != nil || next > end {
			return nil, fmt.Errorf("FFU validation descriptor %d exceeds declared table boundary", index)
		}
		digest, err := hashRegion(reader, compareOffset, uint64(byteCount))
		if err != nil {
			return nil, fmt.Errorf("hash FFU validation descriptor %d: %w", index, err)
		}
		result = append(result, ValidationDescriptor{
			Index:             index,
			TableOffset:       cursor,
			SectorIndex:       binary.LittleEndian.Uint32(header[0:4]),
			SectorOffset:      binary.LittleEndian.Uint32(header[4:8]),
			ByteCount:         byteCount,
			CompareDataOffset: compareOffset,
			CompareDataSHA256: digest,
		})
		cursor = next
	}
	if cursor != end {
		return nil, fmt.Errorf("FFU validation descriptor table has %d unconsumed bytes", end-cursor)
	}
	return result, nil
}

type blockInterval struct {
	anchor          string
	start           uint64
	end             uint64
	descriptorIndex uint32
	locationIndex   uint32
}

func parseWriteDescriptors(
	reader io.ReaderAt,
	size uint64,
	start uint64,
	end uint64,
	payloadOffset uint64,
	count uint32,
	blockSize uint64,
) ([]WriteDescriptor, uint64, uint64, uint64, []blockInterval, error) {
	cursor := start
	payloadCursor := payloadOffset
	totalBlocks := uint64(0)
	beginningBlocks := uint64(0)
	endingBlocks := uint64(0)
	totalLocations := uint64(0)
	result := make([]WriteDescriptor, 0, count)
	intervals := make([]blockInterval, 0, count)

	for index := uint32(0); index < count; index++ {
		header, err := readRegion(reader, size, cursor, 8, fmt.Sprintf("write descriptor %d", index))
		if err != nil {
			return nil, 0, 0, 0, nil, err
		}
		locationCount := binary.LittleEndian.Uint32(header[0:4])
		blockCount := binary.LittleEndian.Uint32(header[4:8])
		if locationCount == 0 || blockCount == 0 {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d has zero locations or blocks", index)
		}
		totalLocations, err = checkedAdd(totalLocations, uint64(locationCount))
		if err != nil || totalLocations > maxPlanLocationCount {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU location count exceeds read-only planning limit %d", maxPlanLocationCount)
		}
		locationsBytes, err := checkedMul(uint64(locationCount), 8)
		if err != nil {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d location length overflows", index)
		}
		locationsOffset, err := checkedAdd(cursor, 8)
		if err != nil {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d location offset overflows", index)
		}
		next, err := checkedAdd(locationsOffset, locationsBytes)
		if err != nil || next > end {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d exceeds declared table boundary", index)
		}
		payloadLength, err := checkedMul(uint64(blockCount), blockSize)
		if err != nil {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d payload length overflows", index)
		}
		payloadNext, err := checkedAdd(payloadCursor, payloadLength)
		if err != nil {
			return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d payload boundary overflows", index)
		}

		locations := make([]DiskLocation, 0, locationCount)
		for locationIndex := uint32(0); locationIndex < locationCount; locationIndex++ {
			offset, err := checkedAdd(locationsOffset, uint64(locationIndex)*8)
			if err != nil {
				return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d location %d offset overflows", index, locationIndex)
			}
			locationBytes, err := readRegion(reader, size, offset, 8, fmt.Sprintf("write descriptor %d location %d", index, locationIndex))
			if err != nil {
				return nil, 0, 0, 0, nil, err
			}
			method := binary.LittleEndian.Uint32(locationBytes[0:4])
			blockIndex := binary.LittleEndian.Uint32(locationBytes[4:8])
			blockEnd, err := checkedAdd(uint64(blockIndex), uint64(blockCount))
			if err != nil {
				return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d location %d block range overflows", index, locationIndex)
			}
			anchor := ""
			switch method {
			case diskAccessBegin:
				anchor = "begin"
				if blockEnd > beginningBlocks {
					beginningBlocks = blockEnd
				}
			case diskAccessEnd:
				anchor = "end"
				if blockEnd > endingBlocks {
					endingBlocks = blockEnd
				}
			default:
				return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor %d location %d uses unsupported disk access method %d", index, locationIndex, method)
			}
			locations = append(locations, DiskLocation{
				Index:        locationIndex,
				AccessMethod: method,
				Anchor:       anchor,
				BlockIndex:   blockIndex,
				BlockEnd:     blockEnd,
			})
			intervals = append(intervals, blockInterval{
				anchor:          anchor,
				start:           uint64(blockIndex),
				end:             blockEnd,
				descriptorIndex: index,
				locationIndex:   locationIndex,
			})
		}
		result = append(result, WriteDescriptor{
			Index:         index,
			TableOffset:   cursor,
			LocationCount: locationCount,
			BlockCount:    blockCount,
			PayloadOffset: payloadCursor,
			PayloadLength: payloadLength,
			Locations:     locations,
		})
		totalBlocks, err = checkedAdd(totalBlocks, uint64(blockCount))
		if err != nil {
			return nil, 0, 0, 0, nil, errors.New("FFU total payload block count overflows")
		}
		payloadCursor = payloadNext
		cursor = next
	}
	if cursor != end {
		return nil, 0, 0, 0, nil, fmt.Errorf("FFU write descriptor table has %d unconsumed bytes", end-cursor)
	}
	return result, totalBlocks, beginningBlocks, endingBlocks, intervals, nil
}

func detectSameAnchorOverlaps(intervals []blockInterval) []DestinationOverlap {
	sorted := append([]blockInterval(nil), intervals...)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].anchor != sorted[right].anchor {
			return sorted[left].anchor < sorted[right].anchor
		}
		if sorted[left].start != sorted[right].start {
			return sorted[left].start < sorted[right].start
		}
		if sorted[left].end != sorted[right].end {
			return sorted[left].end < sorted[right].end
		}
		if sorted[left].descriptorIndex != sorted[right].descriptorIndex {
			return sorted[left].descriptorIndex < sorted[right].descriptorIndex
		}
		return sorted[left].locationIndex < sorted[right].locationIndex
	})

	result := make([]DestinationOverlap, 0)
	var active blockInterval
	haveActive := false
	for _, current := range sorted {
		if !haveActive || current.anchor != active.anchor || current.start >= active.end {
			active = current
			haveActive = true
			continue
		}
		overlapEnd := current.end
		if active.end < overlapEnd {
			overlapEnd = active.end
		}
		result = append(result, DestinationOverlap{
			Anchor:                current.anchor,
			FirstDescriptorIndex:  active.descriptorIndex,
			FirstLocationIndex:    active.locationIndex,
			SecondDescriptorIndex: current.descriptorIndex,
			SecondLocationIndex:   current.locationIndex,
			OverlapStartBlock:     current.start,
			OverlapEndBlock:       overlapEnd,
		})
		if current.end > active.end {
			active = current
		}
	}
	return result
}

func payloadRange(index, count uint32, end uint64) PayloadTableRange {
	return PayloadTableRange{BlockIndex: index, BlockCount: count, BlockEnd: end}
}

func hashRegion(reader io.ReaderAt, offset, length uint64) (string, error) {
	section := io.NewSectionReader(reader, int64(offset), int64(length))
	digest := sha256.New()
	copied, err := io.Copy(digest, section)
	if err != nil {
		return "", err
	}
	if copied != int64(length) {
		return "", fmt.Errorf("read %d of %d bytes", copied, length)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func descriptorPlanDigest(plan DescriptorPlan) string {
	digest := sha256.New()
	writeDigestUint64(digest, uint64(plan.Schema))
	writeDigestUint64(digest, uint64(plan.StoreMajorVersion))
	writeDigestUint64(digest, uint64(plan.StoreMinorVersion))
	writeDigestUint64(digest, plan.SourceFileSize)
	writeDigestUint64(digest, plan.ChunkSizeBytes)
	writeDigestUint64(digest, plan.BlockSizeBytes)
	writeDigestUint64(digest, plan.ValidationDescriptorOffset)
	writeDigestUint64(digest, plan.WriteDescriptorOffset)
	writeDigestUint64(digest, plan.WriteDescriptorEnd)
	writeDigestUint64(digest, plan.PayloadOffset)
	writeDigestUint64(digest, plan.PayloadLength)
	writeDigestUint64(digest, plan.PayloadEnd)
	writeDigestUint64(digest, plan.PayloadFileBytes)
	writeDigestUint64(digest, plan.TrailingFileBytes)
	writeDigestUint64(digest, plan.TotalPayloadBlocks)
	writeDigestUint64(digest, plan.BeginningExtentBlocks)
	writeDigestUint64(digest, plan.EndingExtentBlocks)
	writeDigestUint64(digest, plan.MinimumTargetBlocks)
	writeDigestUint64(digest, plan.MinimumTargetBytes)
	writeDigestRange(digest, plan.InitialTable)
	writeDigestRange(digest, plan.FlashOnlyTable)
	writeDigestRange(digest, plan.FinalTable)
	writeDigestUint64(digest, uint64(len(plan.ValidationDescriptors)))
	for _, validation := range plan.ValidationDescriptors {
		writeDigestUint64(digest, uint64(validation.Index))
		writeDigestUint64(digest, validation.TableOffset)
		writeDigestUint64(digest, uint64(validation.SectorIndex))
		writeDigestUint64(digest, uint64(validation.SectorOffset))
		writeDigestUint64(digest, uint64(validation.ByteCount))
		writeDigestUint64(digest, validation.CompareDataOffset)
		writeDigestString(digest, validation.CompareDataSHA256)
	}
	writeDigestUint64(digest, uint64(len(plan.WriteDescriptors)))
	for _, descriptor := range plan.WriteDescriptors {
		writeDigestUint64(digest, uint64(descriptor.Index))
		writeDigestUint64(digest, descriptor.TableOffset)
		writeDigestUint64(digest, uint64(descriptor.LocationCount))
		writeDigestUint64(digest, uint64(descriptor.BlockCount))
		writeDigestUint64(digest, descriptor.PayloadOffset)
		writeDigestUint64(digest, descriptor.PayloadLength)
		for _, location := range descriptor.Locations {
			writeDigestUint64(digest, uint64(location.Index))
			writeDigestUint64(digest, uint64(location.AccessMethod))
			writeDigestUint64(digest, uint64(location.BlockIndex))
			writeDigestUint64(digest, location.BlockEnd)
		}
	}
	writeDigestUint64(digest, uint64(len(plan.DestinationOverlaps)))
	for _, overlap := range plan.DestinationOverlaps {
		writeDigestString(digest, overlap.Anchor)
		writeDigestUint64(digest, uint64(overlap.FirstDescriptorIndex))
		writeDigestUint64(digest, uint64(overlap.FirstLocationIndex))
		writeDigestUint64(digest, uint64(overlap.SecondDescriptorIndex))
		writeDigestUint64(digest, uint64(overlap.SecondLocationIndex))
		writeDigestUint64(digest, overlap.OverlapStartBlock)
		writeDigestUint64(digest, overlap.OverlapEndBlock)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeDigestRange(digest hash.Hash, value PayloadTableRange) {
	writeDigestUint64(digest, uint64(value.BlockIndex))
	writeDigestUint64(digest, uint64(value.BlockCount))
	writeDigestUint64(digest, value.BlockEnd)
}

func writeDigestUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeDigestString(digest hash.Hash, value string) {
	writeDigestUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}
