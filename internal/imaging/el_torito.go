package imaging

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	elToritoPlanSchema            = 1
	elToritoCatalogEntries        = opticalSectorSize / 32
	elToritoValidationEntrySize   = 32
	elToritoVirtualSectorSize     = uint64(512)
	elToritoAutoExpandMinimumLBAs = uint64(0x1000)
	elToritoPlatformEFI           = byte(0xef)
	elToritoMediaNoEmulation      = byte(0)
	elToritoBootable              = byte(0x88)
	elToritoNotBootable           = byte(0x00)
	elToritoSectionHeader         = byte(0x90)
	elToritoFinalSectionHeader    = byte(0x91)
	elToritoSectionEntryExtension = byte(0x44)
	elToritoHashBufferSize        = 64 * 1024
)

var elToritoSystemID = func() [32]byte {
	var value [32]byte
	copy(value[:], "EL TORITO SPECIFICATION")
	return value
}()

// ElToritoUEFIImagePlan describes one unambiguous, bounded EFI no-emulation
// boot image embedded in an ISO 9660 El Torito catalog. It is read-only evidence,
// not a bootability or firmware-acceptance claim.
type ElToritoUEFIImagePlan struct {
	Schema                       int      `json:"schema"`
	SourceSize                   uint64   `json:"source_size"`
	VolumeSpaceSectors           uint32   `json:"volume_space_sectors"`
	CatalogLBA                   uint32   `json:"catalog_lba"`
	CatalogSHA256                string   `json:"catalog_sha256"`
	EntryIndex                   int      `json:"entry_index"`
	PlatformID                   uint8    `json:"platform_id"`
	MediaType                    uint8    `json:"media_type"`
	LoadSegment                  uint16   `json:"load_segment"`
	SystemType                   uint8    `json:"system_type"`
	DeclaredVirtualSectors       uint16   `json:"declared_virtual_sectors"`
	ImageLBA                     uint32   `json:"image_lba"`
	ImageOffset                  uint64   `json:"image_offset"`
	ImageLength                  uint64   `json:"image_length"`
	AutoExpandedSmallSectorCount bool     `json:"auto_expanded_small_sector_count"`
	ExpansionEndLBA              uint32   `json:"expansion_end_lba"`
	ImageSHA256                  string   `json:"image_sha256"`
	PlanSHA256                   string   `json:"plan_sha256"`
	Limitations                  []string `json:"limitations"`
}

type elToritoBootEntry struct {
	index       int
	platform    byte
	mediaType   byte
	loadSegment uint16
	systemType  byte
	sectorCount uint16
	imageLBA    uint32
}

// PlanElToritoUEFIImage validates the ISO descriptors and one complete El
// Torito catalog sector, then hashes exactly one unambiguous EFI no-emulation
// image. No path, target, mount, or privileged operation is accepted.
func PlanElToritoUEFIImage(ctx context.Context, reader io.ReaderAt, size int64) (ElToritoUEFIImagePlan, error) {
	if ctx == nil {
		return ElToritoUEFIImagePlan{}, errors.New("el Torito planning context is nil")
	}
	if err := ctx.Err(); err != nil {
		return ElToritoUEFIImagePlan{}, err
	}
	if reader == nil || size <= 0 {
		return ElToritoUEFIImagePlan{}, errors.New("el Torito source must be a non-empty random-access image")
	}

	volumeSectors, catalogLBA, err := locateElToritoCatalog(reader, size)
	if err != nil {
		return ElToritoUEFIImagePlan{}, err
	}
	catalogOffset := uint64(catalogLBA) * uint64(opticalSectorSize)
	catalog := make([]byte, opticalSectorSize)
	if err := readElToritoExact(reader, catalog, catalogOffset, uint64(size), "boot catalog"); err != nil {
		return ElToritoUEFIImagePlan{}, err
	}
	if err := validateElToritoCatalogHeader(catalog[:elToritoValidationEntrySize]); err != nil {
		return ElToritoUEFIImagePlan{}, err
	}
	candidate, allBootLBAs, err := selectElToritoUEFIEntry(catalog)
	if err != nil {
		return ElToritoUEFIImagePlan{}, err
	}

	volumeBytes := uint64(volumeSectors) * uint64(opticalSectorSize)
	if volumeBytes > uint64(size) {
		return ElToritoUEFIImagePlan{}, fmt.Errorf("source ISO volume declares %d bytes but source contains %d", volumeBytes, size)
	}
	imageOffset := uint64(candidate.imageLBA) * uint64(opticalSectorSize)
	if candidate.imageLBA == 0 || imageOffset >= volumeBytes {
		return ElToritoUEFIImagePlan{}, fmt.Errorf("el Torito EFI image LBA %d is outside the ISO volume", candidate.imageLBA)
	}

	imageLength := uint64(candidate.sectorCount) * elToritoVirtualSectorSize
	var expansionEnd uint32
	autoExpanded := false
	if candidate.sectorCount <= 1 {
		nextLBA := volumeSectors
		for _, lba := range allBootLBAs {
			if lba > candidate.imageLBA && lba < nextLBA {
				nextLBA = lba
			}
		}
		if nextLBA <= candidate.imageLBA {
			return ElToritoUEFIImagePlan{}, errors.New("el Torito EFI image has no bounded end LBA")
		}
		gap := uint64(nextLBA - candidate.imageLBA)
		if gap >= elToritoAutoExpandMinimumLBAs {
			imageLength = gap * uint64(opticalSectorSize)
			expansionEnd = nextLBA
			autoExpanded = true
		}
	}
	if imageLength == 0 {
		return ElToritoUEFIImagePlan{}, errors.New("el Torito EFI image declares zero length and is too small for safe auto-expansion")
	}
	imageEnd := imageOffset + imageLength
	if imageEnd < imageOffset || imageEnd > volumeBytes || imageEnd > uint64(size) {
		return ElToritoUEFIImagePlan{}, fmt.Errorf("el Torito EFI image extent [%d,%d) is outside the ISO volume", imageOffset, imageEnd)
	}

	imageDigest, err := hashElToritoRange(ctx, reader, imageOffset, imageLength)
	if err != nil {
		return ElToritoUEFIImagePlan{}, err
	}
	catalogDigest := sha256.Sum256(catalog)
	plan := ElToritoUEFIImagePlan{
		Schema:                       elToritoPlanSchema,
		SourceSize:                   uint64(size),
		VolumeSpaceSectors:           volumeSectors,
		CatalogLBA:                   catalogLBA,
		CatalogSHA256:                hex.EncodeToString(catalogDigest[:]),
		EntryIndex:                   candidate.index,
		PlatformID:                   candidate.platform,
		MediaType:                    candidate.mediaType,
		LoadSegment:                  candidate.loadSegment,
		SystemType:                   candidate.systemType,
		DeclaredVirtualSectors:       candidate.sectorCount,
		ImageLBA:                     candidate.imageLBA,
		ImageOffset:                  imageOffset,
		ImageLength:                  imageLength,
		AutoExpandedSmallSectorCount: autoExpanded,
		ExpansionEndLBA:              expansionEnd,
		ImageSHA256:                  hex.EncodeToString(imageDigest[:]),
		Limitations: []string{
			"only one unambiguous EFI no-emulation El Torito image is accepted",
			"catalog validation and content hashing do not prove firmware bootability or Secure Boot acceptance",
			"small declared sector counts are expanded only under the pinned Rufus/libcdio 8 MiB compatibility rule",
			"no path, mount, target, privileged operation, or automatic write-mode selection is performed",
		},
	}
	plan.PlanSHA256 = elToritoPlanDigest(plan)
	return plan, nil
}

// ExtractElToritoUEFIImage streams the exact planned range to writer and
// rehashes it. A changed source is reported even if the caller's writer has
// already received bytes; callers needing atomic publication must provide it.
func ExtractElToritoUEFIImage(ctx context.Context, reader io.ReaderAt, size int64, writer io.Writer) (ElToritoUEFIImagePlan, error) {
	if writer == nil {
		return ElToritoUEFIImagePlan{}, errors.New("el Torito extraction writer is nil")
	}
	plan, err := PlanElToritoUEFIImage(ctx, reader, size)
	if err != nil {
		return plan, err
	}
	digest, err := copyElToritoRange(ctx, reader, writer, plan.ImageOffset, plan.ImageLength)
	if err != nil {
		return plan, err
	}
	expected, _ := hex.DecodeString(plan.ImageSHA256)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return plan, errors.New("el Torito EFI image changed between planning and extraction")
	}
	catalog := make([]byte, opticalSectorSize)
	catalogOffset := uint64(plan.CatalogLBA) * uint64(opticalSectorSize)
	if err := readElToritoExact(reader, catalog, catalogOffset, uint64(size), "boot catalog after extraction"); err != nil {
		return plan, err
	}
	catalogDigest := sha256.Sum256(catalog)
	expectedCatalog, _ := hex.DecodeString(plan.CatalogSHA256)
	if subtle.ConstantTimeCompare(catalogDigest[:], expectedCatalog) != 1 {
		return plan, errors.New("el Torito boot catalog changed between planning and extraction")
	}
	return plan, nil
}

func locateElToritoCatalog(reader io.ReaderAt, size int64) (uint32, uint32, error) {
	var volumeSectors uint32
	var catalogLBA uint32
	foundPVD := false
	foundCatalog := false
	descriptor := make([]byte, opticalSectorSize)
	for sector := firstVolumeDescriptor; sector <= lastVolumeDescriptor; sector++ {
		offset := uint64(sector) * uint64(opticalSectorSize)
		if offset+uint64(opticalSectorSize) > uint64(size) {
			break
		}
		if err := readElToritoExact(reader, descriptor, offset, uint64(size), fmt.Sprintf("volume descriptor %d", sector)); err != nil {
			return 0, 0, err
		}
		if string(descriptor[1:6]) != "CD001" || descriptor[6] != 1 {
			continue
		}
		switch descriptor[0] {
		case 1:
			little := binary.LittleEndian.Uint32(descriptor[80:84])
			big := binary.BigEndian.Uint32(descriptor[84:88])
			if little == 0 || little != big {
				return 0, 0, errors.New("source ISO primary volume descriptor has inconsistent volume-space size")
			}
			if foundPVD && volumeSectors != little {
				return 0, 0, errors.New("source ISO contains conflicting primary volume descriptors")
			}
			volumeSectors = little
			foundPVD = true
		case 0:
			if string(descriptor[7:39]) != string(elToritoSystemID[:]) {
				continue
			}
			value := binary.LittleEndian.Uint32(descriptor[71:75])
			if value == 0 {
				return 0, 0, errors.New("el Torito boot record declares catalog LBA zero")
			}
			if foundCatalog && catalogLBA != value {
				return 0, 0, errors.New("source ISO contains conflicting El Torito boot records")
			}
			catalogLBA = value
			foundCatalog = true
		case 255:
			sector = lastVolumeDescriptor
		}
	}
	if !foundPVD {
		return 0, 0, errors.New("source ISO primary volume descriptor was not found")
	}
	if !foundCatalog {
		return 0, 0, errors.New("el Torito boot record was not found")
	}
	if catalogLBA >= volumeSectors {
		return 0, 0, fmt.Errorf("el Torito catalog LBA %d is outside volume size %d", catalogLBA, volumeSectors)
	}
	return volumeSectors, catalogLBA, nil
}

func validateElToritoCatalogHeader(entry []byte) error {
	if len(entry) != elToritoValidationEntrySize {
		return errors.New("el Torito validation entry has invalid length")
	}
	if entry[0] != 0x01 {
		return fmt.Errorf("el Torito validation header id is %#x, expected 0x1", entry[0])
	}
	if !standardElToritoPlatform(entry[1]) {
		return fmt.Errorf("el Torito validation entry uses unsupported platform %#x", entry[1])
	}
	if entry[30] != 0x55 || entry[31] != 0xaa {
		return errors.New("el Torito validation entry is missing 0x55AA key bytes")
	}
	var sum uint16
	for offset := 0; offset < len(entry); offset += 2 {
		sum += binary.LittleEndian.Uint16(entry[offset : offset+2])
	}
	if sum != 0 {
		return errors.New("el Torito validation entry checksum is invalid")
	}
	return nil
}

func selectElToritoUEFIEntry(catalog []byte) (elToritoBootEntry, []uint32, error) {
	if len(catalog) != int(opticalSectorSize) {
		return elToritoBootEntry{}, nil, errors.New("el Torito catalog must contain exactly one ISO sector")
	}
	validationPlatform := catalog[1]
	candidates := make([]elToritoBootEntry, 0, 2)
	allLBAs := make([]uint32, 0, 8)
	if err := collectElToritoEntry(catalog[32:64], 1, validationPlatform, &candidates, &allLBAs); err != nil {
		return elToritoBootEntry{}, nil, err
	}

	for index := 2; index < int(elToritoCatalogEntries); {
		record := catalog[index*32 : (index+1)*32]
		if allZero(record) {
			break
		}
		indicator := record[0]
		if indicator != elToritoSectionHeader && indicator != elToritoFinalSectionHeader {
			return elToritoBootEntry{}, nil, fmt.Errorf("unsupported El Torito catalog record %#x at entry %d", indicator, index)
		}
		platform := record[1]
		if !standardElToritoPlatform(platform) {
			return elToritoBootEntry{}, nil, fmt.Errorf("el Torito section %d uses unsupported platform %#x", index, platform)
		}
		count := int(binary.LittleEndian.Uint16(record[2:4]))
		if count == 0 || index+count >= int(elToritoCatalogEntries) {
			return elToritoBootEntry{}, nil, fmt.Errorf("el Torito section %d has invalid entry count %d", index, count)
		}
		for current := index + 1; current <= index+count; current++ {
			entry := catalog[current*32 : (current+1)*32]
			if entry[0] == elToritoSectionEntryExtension {
				return elToritoBootEntry{}, nil, fmt.Errorf("el Torito section-entry extensions are unsupported at entry %d", current)
			}
			if err := collectElToritoEntry(entry, current, platform, &candidates, &allLBAs); err != nil {
				return elToritoBootEntry{}, nil, err
			}
		}
		index += count + 1
		if indicator == elToritoFinalSectionHeader {
			for ; index < int(elToritoCatalogEntries); index++ {
				if !allZero(catalog[index*32 : (index+1)*32]) {
					return elToritoBootEntry{}, nil, errors.New("el Torito final section is followed by non-zero catalog data")
				}
			}
			break
		}
	}
	if len(candidates) == 0 {
		return elToritoBootEntry{}, nil, errors.New("el Torito catalog contains no bootable EFI no-emulation image")
	}
	if len(candidates) != 1 {
		return elToritoBootEntry{}, nil, fmt.Errorf("el Torito catalog contains %d bootable EFI no-emulation images; selection is ambiguous", len(candidates))
	}
	return candidates[0], allLBAs, nil
}

func collectElToritoEntry(record []byte, index int, platform byte, candidates *[]elToritoBootEntry, allLBAs *[]uint32) error {
	if len(record) != 32 {
		return fmt.Errorf("el Torito entry %d has invalid length", index)
	}
	if record[0] == elToritoNotBootable {
		return nil
	}
	if record[0] != elToritoBootable {
		return fmt.Errorf("el Torito entry %d has invalid boot indicator %#x", index, record[0])
	}
	if record[1]&0xf0 != 0 || record[1]&0x0f > 4 {
		return fmt.Errorf("el Torito entry %d has unsupported media type %#x", index, record[1])
	}
	entry := elToritoBootEntry{
		index:       index,
		platform:    platform,
		mediaType:   record[1] & 0x0f,
		loadSegment: binary.LittleEndian.Uint16(record[2:4]),
		systemType:  record[4],
		sectorCount: binary.LittleEndian.Uint16(record[6:8]),
		imageLBA:    binary.LittleEndian.Uint32(record[8:12]),
	}
	if entry.imageLBA == 0 {
		return fmt.Errorf("el Torito entry %d has image LBA zero", index)
	}
	*allLBAs = append(*allLBAs, entry.imageLBA)
	if platform != elToritoPlatformEFI {
		return nil
	}
	if entry.mediaType != elToritoMediaNoEmulation {
		return fmt.Errorf("el Torito EFI entry %d uses unsupported emulation media type %d", index, entry.mediaType)
	}
	*candidates = append(*candidates, entry)
	return nil
}

func standardElToritoPlatform(value byte) bool {
	return value == 0x00 || value == 0x01 || value == 0x02 || value == elToritoPlatformEFI
}

func readElToritoExact(reader io.ReaderAt, buffer []byte, offset, size uint64, label string) error {
	end := offset + uint64(len(buffer))
	if end < offset || end > size {
		return fmt.Errorf("el Torito %s extent is outside the source", label)
	}
	n, err := reader.ReadAt(buffer, int64(offset))
	if n != len(buffer) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read El Torito %s: %w", label, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read El Torito %s: %w", label, err)
	}
	return nil
}

func hashElToritoRange(ctx context.Context, reader io.ReaderAt, offset, length uint64) ([sha256.Size]byte, error) {
	result, err := copyElToritoRange(ctx, reader, io.Discard, offset, length)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return result, nil
}

func copyElToritoRange(ctx context.Context, reader io.ReaderAt, writer io.Writer, offset, length uint64) ([sha256.Size]byte, error) {
	if ctx == nil {
		return [sha256.Size]byte{}, errors.New("el Torito copy context is nil")
	}
	if err := ctx.Err(); err != nil {
		return [sha256.Size]byte{}, err
	}
	digest := sha256.New()
	buffer := make([]byte, elToritoHashBufferSize)
	var done uint64
	for done < length {
		if err := ctx.Err(); err != nil {
			return [sha256.Size]byte{}, err
		}
		chunk := uint64(len(buffer))
		if remaining := length - done; remaining < chunk {
			chunk = remaining
		}
		part := buffer[:int(chunk)]
		n, err := reader.ReadAt(part, int64(offset+done))
		if n != len(part) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return [sha256.Size]byte{}, fmt.Errorf("read El Torito EFI image at byte %d: %w", done, err)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return [sha256.Size]byte{}, fmt.Errorf("read El Torito EFI image at byte %d: %w", done, err)
		}
		_, _ = digest.Write(part)
		written, writeErr := writer.Write(part)
		if writeErr != nil {
			return [sha256.Size]byte{}, fmt.Errorf("write El Torito EFI image at byte %d: %w", done, writeErr)
		}
		if written != len(part) {
			return [sha256.Size]byte{}, io.ErrShortWrite
		}
		done += chunk
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func elToritoPlanDigest(plan ElToritoUEFIImagePlan) string {
	digest := sha256.New()
	writeElToritoUint64(digest, uint64(plan.Schema))
	writeElToritoUint64(digest, plan.SourceSize)
	writeElToritoUint64(digest, uint64(plan.VolumeSpaceSectors))
	writeElToritoUint64(digest, uint64(plan.CatalogLBA))
	writeElToritoString(digest, plan.CatalogSHA256)
	writeElToritoUint64(digest, uint64(plan.EntryIndex))
	writeElToritoUint64(digest, uint64(plan.PlatformID))
	writeElToritoUint64(digest, uint64(plan.MediaType))
	writeElToritoUint64(digest, uint64(plan.LoadSegment))
	writeElToritoUint64(digest, uint64(plan.SystemType))
	writeElToritoUint64(digest, uint64(plan.DeclaredVirtualSectors))
	writeElToritoUint64(digest, uint64(plan.ImageLBA))
	writeElToritoUint64(digest, plan.ImageOffset)
	writeElToritoUint64(digest, plan.ImageLength)
	writeElToritoBool(digest, plan.AutoExpandedSmallSectorCount)
	writeElToritoUint64(digest, uint64(plan.ExpansionEndLBA))
	writeElToritoString(digest, plan.ImageSHA256)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeElToritoUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeElToritoString(digest hash.Hash, value string) {
	writeElToritoUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeElToritoBool(digest hash.Hash, value bool) {
	if value {
		writeElToritoUint64(digest, 1)
		return
	}
	writeElToritoUint64(digest, 0)
}
