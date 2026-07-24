// Package ffu provides read-only structural inspection of Microsoft Full Flash
// Update images. It deliberately contains no device-writing code.
package ffu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	securityHeaderBytes    = 32
	imageHeaderBytes       = 24
	storeCommonHeaderBytes = 248

	maxChunkBytes = uint64(1 << 30)
	maxBlockBytes = uint64(1 << 30)
	maxReaderAt   = uint64(1<<63 - 1)
)

// SecurityHeader describes the signed-container prefix. Inspection records the
// catalog and hash-table boundaries but does not yet authenticate either one.
type SecurityHeader struct {
	HeaderSize     uint32 `json:"header_size"`
	Signature      string `json:"signature"`
	ChunkSizeKB    uint32 `json:"chunk_size_kb"`
	ChunkSizeBytes uint64 `json:"chunk_size_bytes"`
	AlgorithmID    uint32 `json:"algorithm_id"`
	CatalogSize    uint32 `json:"catalog_size"`
	HashTableSize  uint32 `json:"hash_table_size"`
}

// ImageHeader describes the FFU image metadata section.
type ImageHeader struct {
	HeaderSize     uint32 `json:"header_size"`
	Signature      string `json:"signature"`
	ManifestLength uint32 `json:"manifest_length"`
	ChunkSizeKB    uint32 `json:"chunk_size_kb"`
}

// StoreHeader describes only the 248-byte prefix common to known FFU store
// layouts. Extensions after FinalTableBlockCount are deliberately unresolved.
// The three table ranges are block ranges within the payload, not indexes into
// the write-descriptor array.
type StoreHeader struct {
	CommonHeaderSize         uint32 `json:"common_header_size"`
	UpdateType               uint32 `json:"update_type"`
	MajorVersion             uint16 `json:"major_version"`
	MinorVersion             uint16 `json:"minor_version"`
	FullFlashMajorVersion    uint16 `json:"full_flash_major_version"`
	FullFlashMinorVersion    uint16 `json:"full_flash_minor_version"`
	PlatformID               string `json:"platform_id,omitempty"`
	BlockSizeBytes           uint32 `json:"block_size_bytes"`
	WriteDescriptorCount     uint32 `json:"write_descriptor_count"`
	WriteDescriptorLength    uint32 `json:"write_descriptor_length"`
	ValidateDescriptorCount  uint32 `json:"validate_descriptor_count"`
	ValidateDescriptorLength uint32 `json:"validate_descriptor_length"`
	InitialTableBlockIndex   uint32 `json:"initial_table_block_index"`
	InitialTableBlockCount   uint32 `json:"initial_table_block_count"`
	InitialTableBlockEnd     uint64 `json:"initial_table_block_end"`
	FlashOnlyTableBlockIndex uint32 `json:"flash_only_table_block_index"`
	FlashOnlyTableBlockCount uint32 `json:"flash_only_table_block_count"`
	FlashOnlyTableBlockEnd   uint64 `json:"flash_only_table_block_end"`
	FinalTableBlockIndex     uint32 `json:"final_table_block_index"`
	FinalTableBlockCount     uint32 `json:"final_table_block_count"`
	FinalTableBlockEnd       uint64 `json:"final_table_block_end"`
}

// Inspection is an immutable read-only description of the FFU regions whose
// boundaries are independently established. Descriptor and payload offsets are
// not reported until the variable store extension is parsed safely.
type Inspection struct {
	Schema                   int            `json:"schema"`
	FileSize                 uint64         `json:"file_size"`
	SecurityHeaderOffset     uint64         `json:"security_header_offset"`
	CatalogOffset            uint64         `json:"catalog_offset"`
	HashTableOffset          uint64         `json:"hash_table_offset"`
	ImageHeaderOffset        uint64         `json:"image_header_offset"`
	ManifestOffset           uint64         `json:"manifest_offset"`
	StoreHeaderOffset        uint64         `json:"store_header_offset"`
	StoreCommonEndOffset     uint64         `json:"store_common_end_offset"`
	MinimumDescriptorBytes   uint64         `json:"minimum_descriptor_bytes"`
	BytesAfterStoreCommon    uint64         `json:"bytes_after_store_common"`
	Security                 SecurityHeader `json:"security"`
	Image                    ImageHeader    `json:"image"`
	Store                    StoreHeader    `json:"store"`
	IntegrityMetadataPresent bool           `json:"integrity_metadata_present"`
	DescriptorLayoutResolved bool           `json:"descriptor_layout_resolved"`
	PayloadLayoutResolved    bool           `json:"payload_layout_resolved"`
	RestorationSupported     bool           `json:"restoration_supported"`
	Limitations              []string       `json:"limitations"`
}

// Inspect validates known FFU header regions without allocating from untrusted
// length fields and without reading or writing any target device.
func Inspect(reader io.ReaderAt, size uint64) (Inspection, error) {
	if reader == nil {
		return Inspection{}, errors.New("FFU reader is nil")
	}
	if size == 0 {
		return Inspection{}, errors.New("FFU image is empty")
	}
	if size > maxReaderAt {
		return Inspection{}, errors.New("FFU image is too large for ReaderAt offsets")
	}

	securityBytes, err := readRegion(reader, size, 0, securityHeaderBytes, "security header")
	if err != nil {
		return Inspection{}, err
	}
	security := SecurityHeader{
		HeaderSize:    binary.LittleEndian.Uint32(securityBytes[0:4]),
		Signature:     string(securityBytes[4:16]),
		ChunkSizeKB:   binary.LittleEndian.Uint32(securityBytes[16:20]),
		AlgorithmID:   binary.LittleEndian.Uint32(securityBytes[20:24]),
		CatalogSize:   binary.LittleEndian.Uint32(securityBytes[24:28]),
		HashTableSize: binary.LittleEndian.Uint32(securityBytes[28:32]),
	}
	if security.HeaderSize != securityHeaderBytes {
		return Inspection{}, fmt.Errorf("unsupported FFU security header size %d", security.HeaderSize)
	}
	if security.Signature != "SignedImage " {
		return Inspection{}, fmt.Errorf("invalid FFU security signature %q", security.Signature)
	}
	chunkBytes, err := checkedMul(uint64(security.ChunkSizeKB), 1024)
	if err != nil || chunkBytes == 0 || chunkBytes > maxChunkBytes || !isPowerOfTwo(chunkBytes) {
		return Inspection{}, fmt.Errorf("invalid FFU chunk size %d KiB", security.ChunkSizeKB)
	}
	security.ChunkSizeBytes = chunkBytes
	if security.CatalogSize == 0 || security.HashTableSize == 0 {
		return Inspection{}, errors.New("FFU security catalog and hash table must both be present")
	}

	catalogOffset := uint64(securityHeaderBytes)
	hashTableOffset, err := checkedAdd(catalogOffset, uint64(security.CatalogSize))
	if err != nil {
		return Inspection{}, errors.New("FFU catalog boundary overflows")
	}
	securityEnd, err := checkedAdd(hashTableOffset, uint64(security.HashTableSize))
	if err != nil {
		return Inspection{}, errors.New("FFU hash-table boundary overflows")
	}
	imageOffset, err := alignUp(securityEnd, chunkBytes)
	if err != nil {
		return Inspection{}, fmt.Errorf("align FFU image header: %w", err)
	}

	imageBytes, err := readRegion(reader, size, imageOffset, imageHeaderBytes, "image header")
	if err != nil {
		return Inspection{}, err
	}
	image := ImageHeader{
		HeaderSize:     binary.LittleEndian.Uint32(imageBytes[0:4]),
		Signature:      string(imageBytes[4:16]),
		ManifestLength: binary.LittleEndian.Uint32(imageBytes[16:20]),
		ChunkSizeKB:    binary.LittleEndian.Uint32(imageBytes[20:24]),
	}
	if image.HeaderSize != imageHeaderBytes {
		return Inspection{}, fmt.Errorf("unsupported FFU image header size %d", image.HeaderSize)
	}
	if image.Signature != "ImageFlash  " {
		return Inspection{}, fmt.Errorf("invalid FFU image signature %q", image.Signature)
	}
	if image.ManifestLength == 0 {
		return Inspection{}, errors.New("FFU manifest is empty")
	}
	if image.ChunkSizeKB != security.ChunkSizeKB {
		return Inspection{}, fmt.Errorf("FFU chunk-size mismatch: security=%d KiB image=%d KiB", security.ChunkSizeKB, image.ChunkSizeKB)
	}
	manifestOffset, err := checkedAdd(imageOffset, imageHeaderBytes)
	if err != nil {
		return Inspection{}, errors.New("FFU manifest offset overflows")
	}
	manifestEnd, err := checkedAdd(manifestOffset, uint64(image.ManifestLength))
	if err != nil {
		return Inspection{}, errors.New("FFU manifest boundary overflows")
	}
	storeOffset, err := alignUp(manifestEnd, chunkBytes)
	if err != nil {
		return Inspection{}, fmt.Errorf("align FFU store header: %w", err)
	}

	storeBytes, err := readRegion(reader, size, storeOffset, storeCommonHeaderBytes, "common store header")
	if err != nil {
		return Inspection{}, err
	}
	store := StoreHeader{
		CommonHeaderSize:         storeCommonHeaderBytes,
		UpdateType:               binary.LittleEndian.Uint32(storeBytes[0:4]),
		MajorVersion:             binary.LittleEndian.Uint16(storeBytes[4:6]),
		MinorVersion:             binary.LittleEndian.Uint16(storeBytes[6:8]),
		FullFlashMajorVersion:    binary.LittleEndian.Uint16(storeBytes[8:10]),
		FullFlashMinorVersion:    binary.LittleEndian.Uint16(storeBytes[10:12]),
		PlatformID:               trimPlatformID(storeBytes[12:204]),
		BlockSizeBytes:           binary.LittleEndian.Uint32(storeBytes[204:208]),
		WriteDescriptorCount:     binary.LittleEndian.Uint32(storeBytes[208:212]),
		WriteDescriptorLength:    binary.LittleEndian.Uint32(storeBytes[212:216]),
		ValidateDescriptorCount:  binary.LittleEndian.Uint32(storeBytes[216:220]),
		ValidateDescriptorLength: binary.LittleEndian.Uint32(storeBytes[220:224]),
		InitialTableBlockIndex:   binary.LittleEndian.Uint32(storeBytes[224:228]),
		InitialTableBlockCount:   binary.LittleEndian.Uint32(storeBytes[228:232]),
		FlashOnlyTableBlockIndex: binary.LittleEndian.Uint32(storeBytes[232:236]),
		FlashOnlyTableBlockCount: binary.LittleEndian.Uint32(storeBytes[236:240]),
		FinalTableBlockIndex:     binary.LittleEndian.Uint32(storeBytes[240:244]),
		FinalTableBlockCount:     binary.LittleEndian.Uint32(storeBytes[244:248]),
	}
	store.InitialTableBlockEnd, err = payloadBlockEnd(store.InitialTableBlockIndex, store.InitialTableBlockCount)
	if err != nil {
		return Inspection{}, fmt.Errorf("FFU initial-table payload range: %w", err)
	}
	store.FlashOnlyTableBlockEnd, err = payloadBlockEnd(store.FlashOnlyTableBlockIndex, store.FlashOnlyTableBlockCount)
	if err != nil {
		return Inspection{}, fmt.Errorf("FFU flash-only-table payload range: %w", err)
	}
	store.FinalTableBlockEnd, err = payloadBlockEnd(store.FinalTableBlockIndex, store.FinalTableBlockCount)
	if err != nil {
		return Inspection{}, fmt.Errorf("FFU final-table payload range: %w", err)
	}

	blockBytes := uint64(store.BlockSizeBytes)
	if blockBytes == 0 || blockBytes > maxBlockBytes || blockBytes%512 != 0 || !isPowerOfTwo(blockBytes) {
		return Inspection{}, fmt.Errorf("invalid FFU block size %d bytes", store.BlockSizeBytes)
	}
	if store.WriteDescriptorCount == 0 || store.WriteDescriptorLength == 0 {
		return Inspection{}, errors.New("FFU contains no write descriptors")
	}
	minimumWriteLength, err := checkedMul(uint64(store.WriteDescriptorCount), 16)
	if err != nil || uint64(store.WriteDescriptorLength) < minimumWriteLength {
		return Inspection{}, fmt.Errorf("FFU write descriptor table is too short for %d entries", store.WriteDescriptorCount)
	}
	if (store.ValidateDescriptorCount == 0) != (store.ValidateDescriptorLength == 0) {
		return Inspection{}, errors.New("FFU validation descriptor count/length are inconsistent")
	}

	storeCommonEnd, err := checkedAdd(storeOffset, storeCommonHeaderBytes)
	if err != nil {
		return Inspection{}, errors.New("FFU common store-header boundary overflows")
	}
	minimumDescriptorBytes, err := checkedAdd(uint64(store.ValidateDescriptorLength), uint64(store.WriteDescriptorLength))
	if err != nil {
		return Inspection{}, errors.New("FFU descriptor lengths overflow")
	}
	if minimumDescriptorBytes > size-storeCommonEnd {
		return Inspection{}, errors.New("FFU is too short to contain its declared descriptor tables after the common store header")
	}

	return Inspection{
		Schema:                   3,
		FileSize:                 size,
		SecurityHeaderOffset:     0,
		CatalogOffset:            catalogOffset,
		HashTableOffset:          hashTableOffset,
		ImageHeaderOffset:        imageOffset,
		ManifestOffset:           manifestOffset,
		StoreHeaderOffset:        storeOffset,
		StoreCommonEndOffset:     storeCommonEnd,
		MinimumDescriptorBytes:   minimumDescriptorBytes,
		BytesAfterStoreCommon:    size - storeCommonEnd,
		Security:                 security,
		Image:                    image,
		Store:                    store,
		IntegrityMetadataPresent: true,
		DescriptorLayoutResolved: false,
		PayloadLayoutResolved:    false,
		RestorationSupported:     false,
		Limitations: []string{
			"only the 248-byte common store prefix is parsed",
			"variable store extensions and descriptor-table offsets are not yet resolved",
			"write and validation descriptor semantics are not yet parsed",
			"payload GPT table ranges are recorded but cannot be bounded until total payload blocks are parsed",
			"the security catalog and chunk hash table are located but not yet authenticated",
			"payload location, compression, and sparse destination mapping are unresolved",
			"split SFU and optimized FFU resize semantics are unsupported",
			"no target device can be written by this package",
		},
	}, nil
}

func readRegion(reader io.ReaderAt, size, offset uint64, length int, label string) ([]byte, error) {
	if length < 0 || offset > size || uint64(length) > size-offset {
		return nil, fmt.Errorf("truncated FFU %s at offset %d", label, offset)
	}
	buffer := make([]byte, length)
	n, err := reader.ReadAt(buffer, int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read FFU %s: %w", label, err)
	}
	if n != length {
		return nil, fmt.Errorf("truncated FFU %s at offset %d", label, offset)
	}
	return buffer, nil
}

func checkedAdd(left, right uint64) (uint64, error) {
	result := left + right
	if result < left {
		return 0, errors.New("unsigned addition overflow")
	}
	return result, nil
}

func checkedMul(left, right uint64) (uint64, error) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, errors.New("unsigned multiplication overflow")
	}
	return left * right, nil
}

func alignUp(value, alignment uint64) (uint64, error) {
	if alignment == 0 {
		return 0, errors.New("zero alignment")
	}
	remainder := value % alignment
	if remainder == 0 {
		return value, nil
	}
	return checkedAdd(value, alignment-remainder)
}

func isPowerOfTwo(value uint64) bool {
	return value != 0 && value&(value-1) == 0
}

func trimPlatformID(raw []byte) string {
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	return strings.TrimSpace(string(raw))
}

func payloadBlockEnd(index, count uint32) (uint64, error) {
	return checkedAdd(uint64(index), uint64(count))
}
