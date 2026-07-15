package imaging

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

const (
	opticalSectorSize       = int64(2048)
	firstVolumeDescriptor   = int64(16)
	lastVolumeDescriptor    = int64(64)
	volumeDescriptorMinSize = 7
	maxGPTEntryTableBytes   = uint64(64 * 1024 * 1024)
)

type ImageInfo struct {
	HasMBR          bool
	HasGPT          bool
	HasISO9660      bool
	HasUDF          bool
	HasMBRPartition bool
}

func (i ImageInfo) HasOpticalFilesystem() bool { return i.HasISO9660 || i.HasUDF }

func (i ImageInfo) LooksLikeRawBootMedia() bool {
	return i.HasGPT || (i.HasMBR && i.HasMBRPartition)
}

func (i ImageInfo) Recognized() bool {
	return i.HasOpticalFilesystem() || i.LooksLikeRawBootMedia()
}

// InspectImage performs a small, read-only preflight inspection. It does not
// claim to prove that media will boot; it rejects files that have neither a
// coherent disk-image layout nor an aligned optical-filesystem signature.
func InspectImage(path string) (ImageInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("open image for inspection: %w", err)
	}
	defer file.Close()
	return InspectOpenFile(file)
}

// InspectOpenFile inspects an already-open, identity-bound source file. The
// caller can therefore guarantee that the file inspected is the file later
// opened for writing, even if the original path is renamed.
func InspectOpenFile(file *os.File) (ImageInfo, error) {
	if file == nil {
		return ImageInfo{}, errors.New("image file is nil")
	}
	stat, err := file.Stat()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("stat image for inspection: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Size() <= 0 {
		return ImageInfo{}, errors.New("image must be a non-empty regular file")
	}
	fileSectors := uint64((stat.Size() + 511) / 512)

	var info ImageInfo
	header := make([]byte, 1024)
	n, err := file.ReadAt(header, 0)
	if err != nil && err != io.EOF {
		return ImageInfo{}, fmt.Errorf("read image header: %w", err)
	}
	header = header[:n]
	inspectMBR(header, fileSectors, &info)
	if len(header) >= 1024 {
		info.HasGPT = inspectGPT(file, header[512:1024], fileSectors)
	}
	inspectOpticalDescriptors(file, &info)
	return info, nil
}

func inspectMBR(header []byte, fileSectors uint64, info *ImageInfo) {
	if len(header) < 512 {
		return
	}
	info.HasMBR = header[510] == 0x55 && header[511] == 0xaa
	if !info.HasMBR {
		return
	}
	for index := 0; index < 4; index++ {
		offset := 446 + index*16
		entry := header[offset : offset+16]
		partitionType := entry[4]
		startLBA := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		sectorCount := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		endLBA := startLBA + sectorCount
		validExtent := startLBA > 0 && startLBA < fileSectors && endLBA >= startLBA
		// Protective MBRs may use 0xffffffff to mean "to the end".
		if sectorCount != 0xffffffff {
			validExtent = validExtent && endLBA <= fileSectors
		}
		if partitionType != 0 && partitionType != 0xee && sectorCount != 0 && validExtent {
			info.HasMBRPartition = true
			return
		}
	}
}

func inspectGPT(file *os.File, sector []byte, fileSectors uint64) bool {
	if len(sector) < 512 || string(sector[:8]) != "EFI PART" {
		return false
	}
	revision := binary.LittleEndian.Uint32(sector[8:12])
	headerSize := binary.LittleEndian.Uint32(sector[12:16])
	storedHeaderCRC := binary.LittleEndian.Uint32(sector[16:20])
	currentLBA := binary.LittleEndian.Uint64(sector[24:32])
	backupLBA := binary.LittleEndian.Uint64(sector[32:40])
	firstUsable := binary.LittleEndian.Uint64(sector[40:48])
	lastUsable := binary.LittleEndian.Uint64(sector[48:56])
	entriesLBA := binary.LittleEndian.Uint64(sector[72:80])
	numEntries := binary.LittleEndian.Uint32(sector[80:84])
	entrySize := binary.LittleEndian.Uint32(sector[84:88])
	storedEntriesCRC := binary.LittleEndian.Uint32(sector[88:92])

	valid := revision == 0x00010000 && headerSize >= 92 && headerSize <= 512 &&
		currentLBA == 1 && backupLBA > currentLBA && backupLBA < fileSectors &&
		firstUsable > currentLBA && lastUsable >= firstUsable && lastUsable < fileSectors &&
		entriesLBA >= 2 && entriesLBA < fileSectors && numEntries > 0 && numEntries <= 1<<20 &&
		entrySize >= 128 && entrySize <= 4096 && entrySize%8 == 0
	if !valid {
		return false
	}
	entriesBytes := uint64(numEntries) * uint64(entrySize)
	entriesSectors := (entriesBytes + 511) / 512
	if entriesBytes == 0 || entriesBytes > maxGPTEntryTableBytes ||
		entriesLBA+entriesSectors < entriesLBA || entriesLBA+entriesSectors > fileSectors {
		return false
	}

	headerCopy := append([]byte(nil), sector[:headerSize]...)
	for index := 16; index < 20; index++ {
		headerCopy[index] = 0
	}
	if storedHeaderCRC == 0 || crc32.ChecksumIEEE(headerCopy) != storedHeaderCRC {
		return false
	}

	entryReader := io.NewSectionReader(file, int64(entriesLBA*512), int64(entriesBytes))
	entry := make([]byte, int(entrySize))
	entryCRC := crc32.NewIEEE()
	hasPartition := false
	for index := uint32(0); index < numEntries; index++ {
		if _, err := io.ReadFull(entryReader, entry); err != nil {
			return false
		}
		_, _ = entryCRC.Write(entry)
		if !allZero(entry[:16]) {
			hasPartition = true
		}
	}
	return hasPartition && entryCRC.Sum32() == storedEntriesCRC
}

func inspectOpticalDescriptors(file *os.File, info *ImageInfo) {
	// ISO9660 and UDF recognition descriptors are aligned to 2048-byte sectors.
	// Requiring the identifiers at the correct offsets avoids recognizing an
	// arbitrary file that merely contains a signature string elsewhere.
	descriptor := make([]byte, opticalSectorSize)
	sawBEA, sawNSR, sawTEA := false, false, false
	for sector := firstVolumeDescriptor; sector <= lastVolumeDescriptor; sector++ {
		n, readErr := file.ReadAt(descriptor, sector*opticalSectorSize)
		if readErr != nil && readErr != io.EOF {
			break
		}
		if n < volumeDescriptorMinSize {
			break
		}
		identifier := string(descriptor[1:6])
		if identifier == "CD001" && descriptor[6] == 1 {
			if descriptor[0] == 1 {
				info.HasISO9660 = true
			}
			if descriptor[0] == 255 {
				break
			}
		}
		if descriptor[0] == 0 && descriptor[6] == 1 {
			switch identifier {
			case "BEA01":
				sawBEA = true
			case "NSR02", "NSR03":
				if sawBEA {
					sawNSR = true
				}
			case "TEA01":
				if sawNSR {
					sawTEA = true
				}
			}
		}
	}
	info.HasUDF = sawBEA && sawNSR && sawTEA
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
