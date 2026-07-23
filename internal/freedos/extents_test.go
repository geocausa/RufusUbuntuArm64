package freedos

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestMediaExtentBytesScaleWithFilesystemStructures(t *testing.T) {
	small, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	large, err := NewMediaPlan(32*1024*1024*1024, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	smallBytes, err := MediaExtentBytes(small)
	if err != nil {
		t.Fatal(err)
	}
	largeBytes, err := MediaExtentBytes(large)
	if err != nil {
		t.Fatal(err)
	}
	if smallBytes == 0 || largeBytes <= smallBytes {
		t.Fatalf("unexpected extent totals: small=%d large=%d", smallBytes, largeBytes)
	}
	if largeBytes >= 128*1024*1024 {
		t.Fatalf("32 GiB FreeDOS extent I/O is not bounded: %d bytes", largeBytes)
	}
	if largeBytes >= large.DiskSizeBytes/256 {
		t.Fatalf("extent coverage %d is too close to 32 GiB device size %d", largeBytes, large.DiskSizeBytes)
	}
	partitionBytes := uint64(large.PartitionSectorCount) * uint64(large.LogicalSectorSize)
	if partitionBytes < large.DiskSizeBytes-3*1024*1024 {
		t.Fatalf("fast extent path unexpectedly shrank the partition: partition=%d device=%d", partitionBytes, large.DiskSizeBytes)
	}
}

func TestWriteAndVerifyMediaExtentsLeaveFreeDataUntouched(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	device := &extentMemoryDevice{data: make([]byte, int(plan.DiskSizeBytes))}
	geometry, err := expectedMediaGeometry(plan)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	rootStart := uint64(plan.PartitionStartSector)*uint64(plan.LogicalSectorSize) + uint64(geometry.dataStartSector)*uint64(plan.LogicalSectorSize)
	commandClusters := uint64(clustersForSize(uint32(len(payload.Command)), geometry.clusterBytes))
	kernelClusters := uint64(clustersForSize(uint32(len(payload.Kernel)), geometry.clusterBytes))
	freeOffset := rootStart + uint64(geometry.clusterBytes)*(1+commandClusters+kernelClusters+7)
	partitionEnd := uint64(plan.PartitionStartSector+plan.PartitionSectorCount) * uint64(plan.LogicalSectorSize)
	if freeOffset >= partitionEnd {
		t.Fatalf("chosen free-data sentinel offset %d exceeds partition end %d", freeOffset, partitionEnd)
	}
	device.data[freeOffset] = 0xa5

	total, err := MediaExtentBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	var lastWrite uint64
	written, err := WriteMediaExtents(context.Background(), device, plan, func(done uint64) error {
		if done <= lastWrite || done > total {
			t.Fatalf("invalid write progress %d after %d of %d", done, lastWrite, total)
		}
		lastWrite = done
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if written.BytesWritten != total || written.SHA256 == "" || lastWrite != total {
		t.Fatalf("incomplete extent write: result=%+v progress=%d total=%d", written, lastWrite, total)
	}
	if device.data[freeOffset] != 0xa5 {
		t.Fatalf("unallocated data byte at %d was changed", freeOffset)
	}

	var lastVerify uint64
	verified, err := VerifyMediaExtents(context.Background(), device, plan, func(done uint64) error {
		if done <= lastVerify || done > total {
			t.Fatalf("invalid verify progress %d after %d of %d", done, lastVerify, total)
		}
		lastVerify = done
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.BytesWritten != total || verified.SHA256 != written.SHA256 || lastVerify != total {
		t.Fatalf("incomplete extent verification: write=%+v verify=%+v progress=%d", written, verified, lastVerify)
	}
	if err := VerifyMediaImage(device.data, plan); err != nil {
		t.Fatalf("extent-created media no longer matches the deterministic structural contract: %v", err)
	}
}

func TestVerifyMediaExtentsRejectsRequiredByteTampering(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	device := &extentMemoryDevice{data: make([]byte, int(plan.DiskSizeBytes))}
	if _, err := WriteMediaExtents(context.Background(), device, plan, nil); err != nil {
		t.Fatal(err)
	}
	device.data[510] ^= 0x01
	result, err := VerifyMediaExtents(context.Background(), device, plan, nil)
	if err == nil || !strings.Contains(err.Error(), "readback differs") {
		t.Fatalf("tampered required byte was accepted: result=%+v err=%v", result, err)
	}
	if result.BytesWritten >= plan.DiskSizeBytes {
		t.Fatalf("tamper report claimed whole-device verification: %+v", result)
	}
}

type extentMemoryDevice struct {
	data []byte
}

func (device *extentMemoryDevice) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(device.data)) {
		return 0, io.ErrShortWrite
	}
	count := copy(device.data[int(offset):], data)
	if count != len(data) {
		return count, io.ErrShortWrite
	}
	return count, nil
}

func (device *extentMemoryDevice) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(device.data)) {
		return 0, io.EOF
	}
	count := copy(data, device.data[int(offset):])
	if count != len(data) {
		return count, io.EOF
	}
	return count, nil
}
