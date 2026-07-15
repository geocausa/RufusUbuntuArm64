package imaging

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
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

// InspectImage performs a deliberately small, read-only preflight inspection.
// It does not attempt to prove bootability; it only identifies signatures that
// distinguish disk-style media from a plain optical ISO image.
func InspectImage(path string) (ImageInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("open image for inspection: %w", err)
	}
	defer f.Close()

	var info ImageInfo
	sector := make([]byte, 1024)
	n, err := io.ReadFull(f, sector)
	if err != nil && err != io.ErrUnexpectedEOF {
		return ImageInfo{}, fmt.Errorf("read image header: %w", err)
	}
	sector = sector[:n]
	if len(sector) >= 512 {
		info.HasMBR = sector[510] == 0x55 && sector[511] == 0xaa
		if info.HasMBR {
			for i := 0; i < 4; i++ {
				offset := 446 + i*16
				entry := sector[offset : offset+16]
				partitionType := entry[4]
				sectorCount := binary.LittleEndian.Uint32(entry[12:16])
				if partitionType != 0 && sectorCount != 0 {
					info.HasMBRPartition = true
					break
				}
			}
		}
	}
	if len(sector) >= 520 {
		info.HasGPT = string(sector[512:520]) == "EFI PART"
	}

	isoHeader := make([]byte, 6)
	if _, err := f.ReadAt(isoHeader, 16*2048); err == nil {
		info.HasISO9660 = isoHeader[0] == 1 && string(isoHeader[1:6]) == "CD001"
	}
	// UDF volume recognition descriptors normally appear shortly after sector 16.
	udfProbe := make([]byte, 128*1024)
	if n, _ := f.ReadAt(udfProbe, 16*2048); n > 0 {
		probe := string(udfProbe[:n])
		info.HasUDF = strings.Contains(probe, "NSR02") || strings.Contains(probe, "NSR03")
	}
	return info, nil
}
