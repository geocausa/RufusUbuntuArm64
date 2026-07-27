package freedos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const MediaVerificationScope = "required-filesystem-extents"

type mediaExtent struct {
	name   string
	offset int64
	length uint64
	data   []byte
}

// MediaExtentBytes returns the number of device bytes that must be changed and
// verified for the reviewed FreeDOS layout. Free data clusters are deliberately
// excluded: exhaustive whole-device testing belongs to the separate USB
// qualification workflow, not ordinary FreeDOS creation.
func MediaExtentBytes(plan MediaPlan) (uint64, error) {
	_, total, err := plannedMediaExtents(plan)
	return total, err
}

// WriteMediaExtents writes only the final safety-critical FreeDOS extents at
// their reviewed offsets. It retains the full-size FAT32 partition while
// avoiding writes to unallocated data clusters.
func WriteMediaExtents(ctx context.Context, writer io.WriterAt, plan MediaPlan, progress func(uint64) error) (MediaStreamResult, error) {
	if writer == nil {
		return MediaStreamResult{}, errors.New("FreeDOS extent writer is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	extents, total, err := plannedMediaExtents(plan)
	if err != nil {
		return MediaStreamResult{}, err
	}
	digest := sha256.New()
	zero := make([]byte, mediaStreamBufferSize)
	var written uint64
	for _, extent := range extents {
		if err := ctx.Err(); err != nil {
			return MediaStreamResult{BytesWritten: written}, err
		}
		var header [16]byte
		binary.LittleEndian.PutUint64(header[0:8], uint64(extent.offset))
		binary.LittleEndian.PutUint64(header[8:16], extent.length)
		_, _ = digest.Write(header[:])
		for position := uint64(0); position < extent.length; {
			if err := ctx.Err(); err != nil {
				return MediaStreamResult{BytesWritten: written}, err
			}
			chunk := uint64(mediaStreamBufferSize)
			if remaining := extent.length - position; chunk > remaining {
				chunk = remaining
			}
			var part []byte
			if extent.data == nil {
				part = zero[:int(chunk)]
			} else {
				part = extent.data[int(position):int(position+chunk)]
			}
			accepted, writeErr := writer.WriteAt(part, extent.offset+int64(position))
			if accepted < 0 || accepted > len(part) {
				return MediaStreamResult{BytesWritten: written}, errors.New("FreeDOS extent writer returned an invalid byte count")
			}
			if accepted > 0 {
				_, _ = digest.Write(part[:accepted])
				position += uint64(accepted)
				written += uint64(accepted)
				if progress != nil {
					if err := progress(written); err != nil {
						return MediaStreamResult{BytesWritten: written}, err
					}
				}
			}
			if writeErr != nil {
				return MediaStreamResult{BytesWritten: written}, fmt.Errorf("write FreeDOS %s at byte %d: %w", extent.name, extent.offset+int64(position), writeErr)
			}
			if accepted != len(part) {
				return MediaStreamResult{BytesWritten: written}, io.ErrShortWrite
			}
		}
	}
	if written != total {
		return MediaStreamResult{BytesWritten: written}, fmt.Errorf("FreeDOS extent writer accepted %d bytes; expected %d", written, total)
	}
	return MediaStreamResult{BytesWritten: written, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

// VerifyMediaExtents compares every required final extent after synchronization.
// The returned digest binds each extent offset, length, and expected byte stream.
func VerifyMediaExtents(ctx context.Context, reader io.ReaderAt, plan MediaPlan, progress func(uint64) error) (MediaStreamResult, error) {
	if reader == nil {
		return MediaStreamResult{}, errors.New("FreeDOS extent readback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	extents, total, err := plannedMediaExtents(plan)
	if err != nil {
		return MediaStreamResult{}, err
	}
	digest := sha256.New()
	zero := make([]byte, mediaStreamBufferSize)
	actual := make([]byte, mediaStreamBufferSize)
	var verified uint64
	for _, extent := range extents {
		if err := ctx.Err(); err != nil {
			return MediaStreamResult{BytesWritten: verified}, err
		}
		var header [16]byte
		binary.LittleEndian.PutUint64(header[0:8], uint64(extent.offset))
		binary.LittleEndian.PutUint64(header[8:16], extent.length)
		_, _ = digest.Write(header[:])
		for position := uint64(0); position < extent.length; {
			if err := ctx.Err(); err != nil {
				return MediaStreamResult{BytesWritten: verified}, err
			}
			chunk := uint64(mediaStreamBufferSize)
			if remaining := extent.length - position; chunk > remaining {
				chunk = remaining
			}
			var expected []byte
			if extent.data == nil {
				expected = zero[:int(chunk)]
			} else {
				expected = extent.data[int(position):int(position+chunk)]
			}
			got := actual[:int(chunk)]
			count, readErr := reader.ReadAt(got, extent.offset+int64(position))
			if count < 0 || count > len(got) {
				return MediaStreamResult{BytesWritten: verified}, errors.New("FreeDOS extent reader returned an invalid byte count")
			}
			if count > 0 {
				if !bytes.Equal(got[:count], expected[:count]) {
					for index := 0; index < count; index++ {
						if got[index] != expected[index] {
							absolute := extent.offset + int64(position) + int64(index)
							return MediaStreamResult{BytesWritten: verified + uint64(index)}, fmt.Errorf("FreeDOS readback differs at byte %d in %s", absolute, extent.name)
						}
					}
				}
				_, _ = digest.Write(expected[:count])
				position += uint64(count)
				verified += uint64(count)
				if progress != nil {
					if err := progress(verified); err != nil {
						return MediaStreamResult{BytesWritten: verified}, err
					}
				}
			}
			if readErr != nil {
				return MediaStreamResult{BytesWritten: verified}, fmt.Errorf("read FreeDOS %s at byte %d: %w", extent.name, extent.offset+int64(position), readErr)
			}
			if count != len(got) {
				return MediaStreamResult{BytesWritten: verified}, io.ErrUnexpectedEOF
			}
		}
	}
	if verified != total {
		return MediaStreamResult{BytesWritten: verified}, fmt.Errorf("FreeDOS extent verifier compared %d bytes; expected %d", verified, total)
	}
	return MediaStreamResult{BytesWritten: verified, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

func plannedMediaExtents(plan MediaPlan) ([]mediaExtent, uint64, error) {
	source, err := NewMediaImageSource(plan)
	if err != nil {
		return nil, 0, err
	}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		return nil, 0, err
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		return nil, 0, fmt.Errorf("FreeDOS payload contract: %w", err)
	}

	sectorSize := uint64(plan.LogicalSectorSize)
	partitionStart := uint64(plan.PartitionStartSector) * sectorSize
	partitionEnd := partitionStart + uint64(plan.PartitionSectorCount)*sectorSize
	fat1Start := partitionStart + uint64(geometry.reservedSectors)*sectorSize
	fatBytes := uint64(geometry.fatSectors) * sectorSize
	fat2Start := fat1Start + fatBytes
	rootStart := partitionStart + uint64(geometry.dataStartSector)*sectorSize
	commandClusters := uint64(clustersForSize(uint32(len(payload.Command)), geometry.clusterBytes))
	kernelClusters := uint64(clustersForSize(uint32(len(payload.Kernel)), geometry.clusterBytes))
	commandStart := rootStart + uint64(geometry.clusterBytes)
	kernelStart := commandStart + commandClusters*uint64(geometry.clusterBytes)

	region := func(offset uint64, name string) ([]byte, error) {
		for _, candidate := range source.regions {
			if candidate.offset == int64(offset) {
				return candidate.data, nil
			}
		}
		return nil, fmt.Errorf("missing deterministic FreeDOS %s region at byte %d", name, offset)
	}
	mbr, err := region(0, "MBR")
	if err != nil {
		return nil, 0, err
	}
	boot, err := region(partitionStart, "boot")
	if err != nil {
		return nil, 0, err
	}
	fat1, err := region(fat1Start, "first FAT")
	if err != nil {
		return nil, 0, err
	}
	fat2, err := region(fat2Start, "second FAT")
	if err != nil {
		return nil, 0, err
	}
	root, err := region(rootStart, "root directory")
	if err != nil {
		return nil, 0, err
	}
	command, err := region(commandStart, "COMMAND.COM")
	if err != nil {
		return nil, 0, err
	}
	kernel, err := region(kernelStart, "KERNEL.SYS")
	if err != nil {
		return nil, 0, err
	}

	extents := make([]mediaExtent, 0, 14)
	addData := func(name string, offset uint64, data []byte) {
		if len(data) != 0 {
			extents = append(extents, mediaExtent{name: name, offset: int64(offset), length: uint64(len(data)), data: data})
		}
	}
	addZero := func(name string, offset, length uint64) {
		if length != 0 {
			extents = append(extents, mediaExtent{name: name, offset: int64(offset), length: length})
		}
	}

	addData("MBR", 0, mbr)
	addZero("pre-partition metadata clearing", uint64(len(mbr)), partitionStart-uint64(len(mbr)))
	addData("FAT32 boot and backup regions", partitionStart, boot)
	addZero("remaining FAT32 reserved sectors", partitionStart+uint64(len(boot)), fat1Start-(partitionStart+uint64(len(boot))))
	addData("first FAT allocated prefix", fat1Start, fat1)
	addZero("first FAT free entries", fat1Start+uint64(len(fat1)), fatBytes-uint64(len(fat1)))
	addData("second FAT allocated prefix", fat2Start, fat2)
	addZero("second FAT free entries", fat2Start+uint64(len(fat2)), fatBytes-uint64(len(fat2)))
	addData("root directory", rootStart, root)
	addData("COMMAND.COM", commandStart, command)
	addZero("COMMAND.COM cluster slack", commandStart+uint64(len(command)), commandClusters*uint64(geometry.clusterBytes)-uint64(len(command)))
	addData("KERNEL.SYS", kernelStart, kernel)
	addZero("KERNEL.SYS cluster slack", kernelStart+uint64(len(kernel)), kernelClusters*uint64(geometry.clusterBytes)-uint64(len(kernel)))
	addZero("backup partition metadata clearing", partitionEnd, plan.DiskSizeBytes-partitionEnd)

	var total uint64
	var previousEnd uint64
	for index, extent := range extents {
		if extent.offset < 0 || extent.length == 0 {
			return nil, 0, fmt.Errorf("invalid FreeDOS extent %q", extent.name)
		}
		start := uint64(extent.offset)
		end := start + extent.length
		if end < start || end > plan.DiskSizeBytes {
			return nil, 0, fmt.Errorf("FreeDOS extent %q exceeds the reviewed device", extent.name)
		}
		if extent.data != nil && uint64(len(extent.data)) != extent.length {
			return nil, 0, fmt.Errorf("FreeDOS extent %q data length is inconsistent", extent.name)
		}
		if index > 0 && start < previousEnd {
			return nil, 0, fmt.Errorf("FreeDOS extent %q overlaps the previous extent", extent.name)
		}
		if total > ^uint64(0)-extent.length {
			return nil, 0, errors.New("FreeDOS extent byte total overflow")
		}
		total += extent.length
		previousEnd = end
	}
	if total == 0 || total >= plan.DiskSizeBytes {
		return nil, 0, errors.New("FreeDOS required extents do not preserve free data space")
	}
	return extents, total, nil
}
