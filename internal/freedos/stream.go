package freedos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

const mediaStreamBufferSize = 1024 * 1024

type mediaRegion struct {
	offset int64
	data   []byte
}

// MediaImageSource is a read-only, sparse representation of the reviewed
// whole-disk image. Unlisted bytes are deterministically zero, so devices up to
// the reviewed FAT32 boundary can be written and compared with bounded memory.
type MediaImageSource struct {
	plan    MediaPlan
	regions []mediaRegion
}

// MediaStreamResult reports how many bytes were accepted and the digest over
// exactly those bytes. On failure, BytesWritten may be non-zero and callers
// must conservatively treat the target as changed.
type MediaStreamResult struct {
	BytesWritten uint64 `json:"bytes_written"`
	SHA256       string `json:"sha256,omitempty"`
}

// NewMediaImageSource builds the small set of non-zero regions required by the
// deterministic media contract. It opens no file and grants no device access.
func NewMediaImageSource(plan MediaPlan) (*MediaImageSource, error) {
	if err := ValidateMediaPlan(plan); err != nil {
		return nil, err
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		return nil, err
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		return nil, fmt.Errorf("FreeDOS payload contract: %w", err)
	}
	label, err := canonicalFATLabel(plan.Label)
	if err != nil {
		return nil, err
	}

	mbr := make([]byte, mbrSectorSize)
	entry := mbr[446:462]
	entry[0] = 0x80
	startCHS := encodeLegacyCHS(uint64(plan.PartitionStartSector), plan.Heads, plan.SectorsPerTrack)
	endCHS := encodeLegacyCHS(uint64(plan.PartitionStartSector)+uint64(plan.PartitionSectorCount)-1, plan.Heads, plan.SectorsPerTrack)
	copy(entry[1:4], startCHS[:])
	entry[4] = 0x0c
	copy(entry[5:8], endCHS[:])
	binary.LittleEndian.PutUint32(entry[8:12], plan.PartitionStartSector)
	binary.LittleEndian.PutUint32(entry[12:16], plan.PartitionSectorCount)
	if err := ApplyRufusMBRCode(mbr); err != nil {
		return nil, fmt.Errorf("apply FreeDOS MBR code: %w", err)
	}

	sectorSize := int(plan.LogicalSectorSize)
	bootPrefix := make([]byte, fat32BackupSector*sectorSize+fat32BootRegionSize)
	for _, base := range []int{0, fat32BackupSector * sectorSize} {
		boot := bootPrefix[base : base+sectorSize]
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
		fsInfo := bootPrefix[sector*sectorSize : (sector+1)*sectorSize]
		binary.LittleEndian.PutUint32(fsInfo[0:4], 0x41615252)
		binary.LittleEndian.PutUint32(fsInfo[484:488], 0x61417272)
		binary.LittleEndian.PutUint32(fsInfo[488:492], freeClusters)
		binary.LittleEndian.PutUint32(fsInfo[492:496], allocatedEnd)
		binary.LittleEndian.PutUint32(fsInfo[508:512], 0xaa550000)
	}
	if err := ApplyFreeDOSFAT32BootRegions(bootPrefix, sectorSize); err != nil {
		return nil, fmt.Errorf("apply FreeDOS FAT32 boot regions: %w", err)
	}

	fatPrefix := make([]byte, int(allocatedEnd)*4)
	putMediaFATEntry(fatPrefix, 0, 0x0ffffff8)
	putMediaFATEntry(fatPrefix, 1, 0x0fffffff)
	putMediaFATEntry(fatPrefix, 2, 0x0fffffff)
	writeMediaContiguousChain(fatPrefix, 3, commandClusters)
	writeMediaContiguousChain(fatPrefix, 3+commandClusters, kernelClusters)

	root := make([]byte, geometry.clusterBytes)
	copy(root[0:11], label[:])
	root[11] = 0x08
	writeMediaDirectoryEntry(root[32:64], commandShortName, 0x06, 3, uint32(len(payload.Command)))
	writeMediaDirectoryEntry(root[64:96], kernelShortName, 0x06, 3+commandClusters, uint32(len(payload.Kernel)))

	partitionStart := int64(plan.PartitionStartSector) * int64(plan.LogicalSectorSize)
	fat1Start := partitionStart + int64(geometry.reservedSectors)*int64(plan.LogicalSectorSize)
	fatBytes := int64(geometry.fatSectors) * int64(plan.LogicalSectorSize)
	rootStart := partitionStart + int64(geometry.dataStartSector)*int64(plan.LogicalSectorSize)
	commandStart := rootStart + int64(geometry.clusterBytes)
	kernelStart := commandStart + int64(commandClusters)*int64(geometry.clusterBytes)
	regions := []mediaRegion{
		{offset: 0, data: mbr},
		{offset: partitionStart, data: bootPrefix},
		{offset: fat1Start, data: fatPrefix},
		{offset: fat1Start + fatBytes, data: append([]byte(nil), fatPrefix...)},
		{offset: rootStart, data: root},
		{offset: commandStart, data: append([]byte(nil), payload.Command...)},
		{offset: kernelStart, data: append([]byte(nil), payload.Kernel...)},
	}
	sort.Slice(regions, func(left, right int) bool { return regions[left].offset < regions[right].offset })
	source := &MediaImageSource{plan: plan, regions: regions}
	if err := source.validateRegions(); err != nil {
		return nil, err
	}
	return source, nil
}

// Size returns the exact whole-disk byte count.
func (source *MediaImageSource) Size() uint64 {
	if source == nil {
		return 0
	}
	return source.plan.DiskSizeBytes
}

// ReadAt returns the deterministic image bytes, synthesizing zero-filled gaps
// without allocating the complete disk image.
func (source *MediaImageSource) ReadAt(buffer []byte, offset int64) (int, error) {
	if source == nil {
		return 0, errors.New("FreeDOS media source is nil")
	}
	if offset < 0 {
		return 0, errors.New("negative FreeDOS media offset")
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	size := int64(source.plan.DiskSizeBytes)
	if offset >= size {
		return 0, io.EOF
	}
	count := len(buffer)
	if remaining := size - offset; int64(count) > remaining {
		count = int(remaining)
	}
	clear(buffer[:count])
	windowEnd := offset + int64(count)
	for _, region := range source.regions {
		regionEnd := region.offset + int64(len(region.data))
		if regionEnd <= offset {
			continue
		}
		if region.offset >= windowEnd {
			break
		}
		start := maxInt64(offset, region.offset)
		end := minInt64(windowEnd, regionEnd)
		copy(buffer[start-offset:end-offset], region.data[start-region.offset:end-region.offset])
	}
	if count != len(buffer) {
		return count, io.EOF
	}
	return count, nil
}

// StreamMediaImage writes the exact deterministic image sequentially with a
// fixed-size buffer. Progress is called only after successfully accepted bytes.
func StreamMediaImage(ctx context.Context, writer io.Writer, plan MediaPlan, progress func(uint64) error) (MediaStreamResult, error) {
	if writer == nil {
		return MediaStreamResult{}, errors.New("FreeDOS media writer is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source, err := NewMediaImageSource(plan)
	if err != nil {
		return MediaStreamResult{}, err
	}
	hash := sha256.New()
	buffer := make([]byte, mediaStreamBufferSize)
	var written uint64
	for written < source.Size() {
		if err := ctx.Err(); err != nil {
			return MediaStreamResult{BytesWritten: written}, err
		}
		chunk := uint64(len(buffer))
		if remaining := source.Size() - written; chunk > remaining {
			chunk = remaining
		}
		part := buffer[:int(chunk)]
		if _, err := source.ReadAt(part, int64(written)); err != nil {
			return MediaStreamResult{BytesWritten: written}, fmt.Errorf("read deterministic FreeDOS media at byte %d: %w", written, err)
		}
		accepted, writeErr := writer.Write(part)
		if accepted < 0 || accepted > len(part) {
			return MediaStreamResult{BytesWritten: written}, errors.New("FreeDOS media writer returned an invalid byte count")
		}
		if accepted > 0 {
			_, _ = hash.Write(part[:accepted])
			written += uint64(accepted)
			if progress != nil {
				if err := progress(written); err != nil {
					return MediaStreamResult{BytesWritten: written}, err
				}
			}
		}
		if writeErr != nil {
			return MediaStreamResult{BytesWritten: written}, writeErr
		}
		if accepted != len(part) {
			return MediaStreamResult{BytesWritten: written}, io.ErrShortWrite
		}
	}
	return MediaStreamResult{BytesWritten: written, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}, nil
}

// VerifyMediaReadback compares every byte of a seekable readback with the sparse
// deterministic source and returns the expected whole-image digest.
func VerifyMediaReadback(ctx context.Context, reader io.ReaderAt, plan MediaPlan) (MediaStreamResult, error) {
	if reader == nil {
		return MediaStreamResult{}, errors.New("FreeDOS media readback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source, err := NewMediaImageSource(plan)
	if err != nil {
		return MediaStreamResult{}, err
	}
	expected := make([]byte, mediaStreamBufferSize)
	actual := make([]byte, mediaStreamBufferSize)
	hash := sha256.New()
	var verified uint64
	for verified < source.Size() {
		if err := ctx.Err(); err != nil {
			return MediaStreamResult{BytesWritten: verified}, err
		}
		chunk := uint64(len(expected))
		if remaining := source.Size() - verified; chunk > remaining {
			chunk = remaining
		}
		want := expected[:int(chunk)]
		got := actual[:int(chunk)]
		if _, err := source.ReadAt(want, int64(verified)); err != nil {
			return MediaStreamResult{BytesWritten: verified}, err
		}
		count, readErr := reader.ReadAt(got, int64(verified))
		if count != len(got) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return MediaStreamResult{BytesWritten: verified + uint64(count)}, fmt.Errorf("read FreeDOS media at byte %d: %w", verified, readErr)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return MediaStreamResult{BytesWritten: verified + uint64(count)}, fmt.Errorf("read FreeDOS media at byte %d: %w", verified, readErr)
		}
		if !bytes.Equal(want, got) {
			for index := range want {
				if want[index] != got[index] {
					return MediaStreamResult{BytesWritten: verified + uint64(index)}, fmt.Errorf("FreeDOS media readback differs at byte %d", verified+uint64(index))
				}
			}
		}
		_, _ = hash.Write(want)
		verified += chunk
	}
	return MediaStreamResult{BytesWritten: verified, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}, nil
}

func (source *MediaImageSource) validateRegions() error {
	size := int64(source.plan.DiskSizeBytes)
	var previousEnd int64
	for index, region := range source.regions {
		if region.offset < 0 || len(region.data) == 0 || region.offset+int64(len(region.data)) > size {
			return errors.New("FreeDOS sparse media region is outside the image")
		}
		if index > 0 && region.offset < previousEnd {
			return errors.New("FreeDOS sparse media regions overlap")
		}
		previousEnd = region.offset + int64(len(region.data))
	}
	return nil
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
