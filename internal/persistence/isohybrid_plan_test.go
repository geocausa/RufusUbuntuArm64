package persistence

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func writeTestMBREntry(image []byte, index int, bootable bool, partitionType byte, start, count uint32) {
	entry := image[446+index*16 : 446+(index+1)*16]
	if bootable {
		entry[0] = 0x80
	}
	entry[4] = partitionType
	binary.LittleEndian.PutUint32(entry[8:12], start)
	binary.LittleEndian.PutUint32(entry[12:16], count)
}

func writeTestISO9660PVD(image []byte, descriptorIndex int) {
	offset := int(isoDescriptorStart) + descriptorIndex*int(isoDescriptorSize)
	image[offset] = 1
	copy(image[offset+1:offset+6], "CD001")
	image[offset+6] = 1
}

func TestBuildPlanAcceptsBoundedISOHybridMetadata(t *testing.T) {
	imageSize := uint64(64 * testMiB)
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	writeTestISO9660PVD(image, 1)
	writeTestMBREntry(image, 0, true, 0x00, 0, uint32(imageSize/sectorSize))
	writeTestMBREntry(image, 1, false, 0xef, 2048, 4096)

	plan, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection())
	if err != nil {
		t.Fatal(err)
	}
	if plan.PartitionTable != TableMBR || plan.PartitionNumber != 3 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestBuildPlanRejectsTypeZeroEntryWithoutISO9660(t *testing.T) {
	imageSize := uint64(64 * testMiB)
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	writeTestMBREntry(image, 0, true, 0x00, 0, uint32(imageSize/sectorSize))

	_, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection())
	if err == nil || !strings.Contains(err.Error(), "type=0x00") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildPlanRejectsISOHybridExtentOutsideImage(t *testing.T) {
	imageSize := uint64(64 * testMiB)
	image := make([]byte, imageSize)
	image[510], image[511] = 0x55, 0xaa
	writeTestISO9660PVD(image, 0)
	writeTestMBREntry(image, 0, true, 0x00, 0, uint32(imageSize/sectorSize)+1)

	_, err := BuildPlan(bytes.NewReader(image), imageSize, 8*1024*testMiB, 2*1024*testMiB, readyDetection())
	if err == nil || !strings.Contains(err.Error(), "image_sectors") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestISO9660DetectionRequiresPrimaryVolumeDescriptor(t *testing.T) {
	image := make([]byte, 64*testMiB)
	offset := int(isoDescriptorStart)
	image[offset] = 0
	copy(image[offset+1:offset+6], "CD001")
	image[offset+6] = 1
	if hasISO9660PrimaryVolumeDescriptor(bytes.NewReader(image), uint64(len(image))) {
		t.Fatal("boot record was accepted without a primary volume descriptor")
	}
	writeTestISO9660PVD(image, 1)
	if !hasISO9660PrimaryVolumeDescriptor(bytes.NewReader(image), uint64(len(image))) {
		t.Fatal("primary volume descriptor was not detected")
	}
}
