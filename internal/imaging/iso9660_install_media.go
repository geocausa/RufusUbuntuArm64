package imaging

import (
	"encoding/binary"
	"io"
	"strings"
)

const (
	maxISO9660DirectoryBytes   = uint32(8 * 1024 * 1024)
	maxISO9660DirectoryRecords = 65536
	iso9660DirectoryFlag       = byte(0x02)
)

type iso9660Directory struct {
	extent uint32
	size   uint32
}

type iso9660Entry struct {
	name      string
	directory bool
	extent    uint32
	size      uint32
}

// inspectISO9660WindowsMarkers performs a bounded read-only scan of the
// primary ISO9660 tree. Windows installation media are admitted only when the
// exact SOURCES/BOOT.WIM marker and at least one supported installation
// payload are present. A fallback EFI loader alone is not Windows evidence.
func inspectISO9660WindowsMarkers(reader io.ReaderAt, imageSize int64, info *ImageInfo) {
	if reader == nil || info == nil || imageSize <= 0 || !info.HasISO9660 {
		return
	}
	root, ok := iso9660RootDirectory(reader, imageSize)
	if !ok {
		return
	}
	rootEntries, ok := readISO9660Directory(reader, imageSize, root)
	if !ok {
		return
	}
	var sources []iso9660Entry
	for _, entry := range rootEntries {
		if entry.directory && entry.name == "SOURCES" {
			sources = append(sources, entry)
		}
	}
	if len(sources) != 1 {
		return
	}
	sourceEntries, ok := readISO9660Directory(reader, imageSize, iso9660Directory{
		extent: sources[0].extent,
		size:   sources[0].size,
	})
	if !ok {
		return
	}
	bootWIM := 0
	installPayload := 0
	for _, entry := range sourceEntries {
		if entry.directory {
			continue
		}
		switch entry.name {
		case "BOOT.WIM":
			bootWIM++
		case "INSTALL.WIM", "INSTALL.ESD", "INSTALL.SWM":
			installPayload++
		}
	}
	info.HasWindowsBootWIM = bootWIM == 1
	info.HasWindowsInstallPayload = installPayload > 0
}

func iso9660RootDirectory(reader io.ReaderAt, imageSize int64) (iso9660Directory, bool) {
	descriptor := make([]byte, opticalSectorSize)
	for sector := firstVolumeDescriptor; sector <= lastVolumeDescriptor; sector++ {
		offset := sector * opticalSectorSize
		if offset < 0 || offset+opticalSectorSize > imageSize {
			return iso9660Directory{}, false
		}
		n, err := reader.ReadAt(descriptor, offset)
		if err != nil && err != io.EOF {
			return iso9660Directory{}, false
		}
		if n < volumeDescriptorMinSize {
			return iso9660Directory{}, false
		}
		if string(descriptor[1:6]) != "CD001" || descriptor[6] != 1 {
			continue
		}
		if descriptor[0] == 255 {
			return iso9660Directory{}, false
		}
		if descriptor[0] != 1 {
			continue
		}
		return parseISO9660DirectoryRecord(descriptor[156:], imageSize)
	}
	return iso9660Directory{}, false
}

func parseISO9660DirectoryRecord(record []byte, imageSize int64) (iso9660Directory, bool) {
	if len(record) < 34 {
		return iso9660Directory{}, false
	}
	recordLength := int(record[0])
	if recordLength < 34 || recordLength > len(record) {
		return iso9660Directory{}, false
	}
	extent := binary.LittleEndian.Uint32(record[2:6])
	size := binary.LittleEndian.Uint32(record[10:14])
	if record[25]&iso9660DirectoryFlag == 0 || !validISO9660Extent(extent, size, imageSize) {
		return iso9660Directory{}, false
	}
	return iso9660Directory{extent: extent, size: size}, true
}

func readISO9660Directory(reader io.ReaderAt, imageSize int64, directory iso9660Directory) ([]iso9660Entry, bool) {
	if !validISO9660Extent(directory.extent, directory.size, imageSize) || directory.size > maxISO9660DirectoryBytes {
		return nil, false
	}
	data := make([]byte, int(directory.size))
	offset := int64(directory.extent) * opticalSectorSize
	if _, err := io.ReadFull(io.NewSectionReader(reader, offset, int64(directory.size)), data); err != nil {
		return nil, false
	}
	entries := make([]iso9660Entry, 0, 64)
	for cursor, records := 0, 0; cursor < len(data); records++ {
		if records >= maxISO9660DirectoryRecords {
			return nil, false
		}
		recordLength := int(data[cursor])
		if recordLength == 0 {
			next := ((cursor / int(opticalSectorSize)) + 1) * int(opticalSectorSize)
			if next <= cursor {
				return nil, false
			}
			cursor = next
			continue
		}
		if recordLength < 34 || cursor+recordLength > len(data) {
			return nil, false
		}
		record := data[cursor : cursor+recordLength]
		identifierLength := int(record[32])
		if identifierLength <= 0 || 33+identifierLength > len(record) {
			return nil, false
		}
		identifier := record[33 : 33+identifierLength]
		cursor += recordLength
		if len(identifier) == 1 && (identifier[0] == 0 || identifier[0] == 1) {
			continue
		}
		name := normalizeISO9660Identifier(identifier)
		if name == "" {
			continue
		}
		extent := binary.LittleEndian.Uint32(record[2:6])
		size := binary.LittleEndian.Uint32(record[10:14])
		if !validISO9660Extent(extent, size, imageSize) {
			return nil, false
		}
		entries = append(entries, iso9660Entry{
			name:      name,
			directory: record[25]&iso9660DirectoryFlag != 0,
			extent:    extent,
			size:      size,
		})
	}
	return entries, true
}

func normalizeISO9660Identifier(identifier []byte) string {
	name := string(identifier)
	if index := strings.IndexByte(name, ';'); index >= 0 {
		name = name[:index]
	}
	name = strings.TrimSuffix(name, ".")
	return strings.ToUpper(name)
}

func microsoftOpticalDescriptor(descriptor []byte) bool {
	if len(descriptor) < 702 || descriptor[0] != 1 || string(descriptor[1:6]) != "CD001" || descriptor[6] != 1 {
		return false
	}
	publisher := normalizeISO9660Metadata(descriptor[318:446])
	preparer := normalizeISO9660Metadata(descriptor[446:574])
	application := normalizeISO9660Metadata(descriptor[574:702])
	return publisher == "MICROSOFT CORPORATION" && strings.Contains(preparer, "MICROSOFT") && strings.HasPrefix(application, "CDIMAGE ")
}

func normalizeISO9660Metadata(value []byte) string {
	return strings.ToUpper(strings.Trim(string(value), " \x00"))
}

func validISO9660Extent(extent, size uint32, imageSize int64) bool {
	if extent == 0 || size == 0 || imageSize <= 0 {
		return false
	}
	offset := uint64(extent) * uint64(opticalSectorSize)
	end := offset + uint64(size)
	return end >= offset && end <= uint64(imageSize)
}
