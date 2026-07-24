package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestPlanHashTableValidatesShapeAndRecordsDigests(t *testing.T) {
	data := hashTableFixture(16, 32)
	catalog := data[securityHeaderBytes : securityHeaderBytes+16]
	table := data[securityHeaderBytes+16 : securityHeaderBytes+16+32]
	for index := range catalog {
		catalog[index] = byte(index + 1)
	}
	for index := range table {
		table[index] = byte(0xa0 + index)
	}

	inspection, plan, err := PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Schema != 3 || plan.Schema != hashTableStructureSchema {
		t.Fatalf("unexpected schemas: inspection=%d plan=%d", inspection.Schema, plan.Schema)
	}
	if plan.AlgorithmID != ffuAlgorithmSHA256 || plan.Algorithm != "SHA-256" || plan.DigestSizeBytes != sha256.Size {
		t.Fatalf("unexpected algorithm contract: %#v", plan)
	}
	if plan.HashEntryCount != 1 || !plan.HashTableShapeValidated {
		t.Fatalf("unexpected hash-table shape: %#v", plan)
	}
	catalogDigest := sha256.Sum256(catalog)
	tableDigest := sha256.Sum256(table)
	if plan.CatalogSHA256 != hex.EncodeToString(catalogDigest[:]) || plan.HashTableSHA256 != hex.EncodeToString(tableDigest[:]) {
		t.Fatalf("unexpected metadata digests: %#v", plan)
	}
	if plan.CatalogAuthenticationAttempted || plan.HashTableCatalogAuthenticated || plan.ContentVerificationAttempted || plan.ContentMatchesHashTable {
		t.Fatalf("unperformed authentication was claimed: %#v", plan)
	}
	if len(plan.PlanSHA256) != sha256.Size*2 || len(plan.Limitations) == 0 {
		t.Fatalf("missing deterministic plan metadata: %#v", plan)
	}

	_, repeated, err := PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if repeated.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("plan digest changed: first=%s repeated=%s", plan.PlanSHA256, repeated.PlanSHA256)
	}
}

func TestPlanHashTableCountsMultipleEntries(t *testing.T) {
	data := hashTableFixture(16, 96)
	_, plan, err := PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if plan.HashEntryCount != 3 || plan.HashTableLength != 96 {
		t.Fatalf("unexpected table count: %#v", plan)
	}
}

func TestPlanHashTableRejectsUnsupportedAlgorithm(t *testing.T) {
	data := hashTableFixture(16, 32)
	binary.LittleEndian.PutUint32(data[20:24], 0x00008004)
	_, _, err := PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "only CALG_SHA_256") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlanHashTableRejectsMalformedLengths(t *testing.T) {
	for _, length := range []uint32{1, 31, 33, 63} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			data := hashTableFixture(16, length)
			_, _, err := PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), "non-zero multiple") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPlanHashTableHonorsCancellation(t *testing.T) {
	data := hashTableFixture(16, 32)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := PlanHashTable(ctx, bytes.NewReader(data), uint64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestPlanHashTableStreamsMetadataWithBoundedReads(t *testing.T) {
	data := hashTableFixture(128*1024, 256*1024)
	reader := &boundedReaderAt{data: data, maximum: ffuHashReadBufferBytes}
	_, plan, err := PlanHashTable(context.Background(), reader, uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if reader.largest > ffuHashReadBufferBytes {
		t.Fatalf("largest read=%d limit=%d", reader.largest, ffuHashReadBufferBytes)
	}
	if plan.HashEntryCount != (256*1024)/sha256.Size {
		t.Fatalf("hash entries=%d", plan.HashEntryCount)
	}
}

func FuzzPlanHashTableDoesNotPanic(f *testing.F) {
	f.Add(hashTableFixture(16, 32))
	f.Add(hashTableFixture(16, 96))
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = PlanHashTable(context.Background(), bytes.NewReader(data), uint64(len(data)))
	})
}

type boundedReaderAt struct {
	data    []byte
	maximum int
	largest int
}

func (reader *boundedReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if len(buffer) > reader.maximum {
		return 0, fmt.Errorf("oversized read %d", len(buffer))
	}
	if len(buffer) > reader.largest {
		reader.largest = len(buffer)
	}
	if offset < 0 || offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	count := copy(buffer, reader.data[offset:])
	if count != len(buffer) {
		return count, io.EOF
	}
	return count, nil
}

func hashTableFixture(catalogSize, hashTableSize uint32) []byte {
	const (
		chunkBytes   = uint64(4096)
		manifestSize = uint32(17)
		blockSize    = uint32(4096)
		writeCount   = uint32(2)
		writeLength  = uint32(32)
	)
	securityEnd := uint64(securityHeaderBytes) + uint64(catalogSize) + uint64(hashTableSize)
	imageOffset := fixtureAlignUp(securityEnd, chunkBytes)
	manifestOffset := imageOffset + imageHeaderBytes
	storeOffset := fixtureAlignUp(manifestOffset+uint64(manifestSize), chunkBytes)
	data := make([]byte, storeOffset+uint64(storeCommonHeaderBytes)+uint64(writeLength)+chunkBytes)

	binary.LittleEndian.PutUint32(data[0:4], securityHeaderBytes)
	copy(data[4:16], "SignedImage ")
	binary.LittleEndian.PutUint32(data[16:20], uint32(chunkBytes/1024))
	binary.LittleEndian.PutUint32(data[20:24], ffuAlgorithmSHA256)
	binary.LittleEndian.PutUint32(data[24:28], catalogSize)
	binary.LittleEndian.PutUint32(data[28:32], hashTableSize)

	binary.LittleEndian.PutUint32(data[imageOffset:imageOffset+4], imageHeaderBytes)
	copy(data[imageOffset+4:imageOffset+16], "ImageFlash  ")
	binary.LittleEndian.PutUint32(data[imageOffset+16:imageOffset+20], manifestSize)
	binary.LittleEndian.PutUint32(data[imageOffset+20:imageOffset+24], uint32(chunkBytes/1024))
	copy(data[manifestOffset:manifestOffset+uint64(manifestSize)], "<FFU test data/>")

	binary.LittleEndian.PutUint32(data[storeOffset:storeOffset+4], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+4:storeOffset+6], 1)
	binary.LittleEndian.PutUint16(data[storeOffset+6:storeOffset+8], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+8:storeOffset+10], 2)
	binary.LittleEndian.PutUint16(data[storeOffset+10:storeOffset+12], 0)
	copy(data[storeOffset+12:storeOffset+204], "RufusArm64.HashTableTest")
	binary.LittleEndian.PutUint32(data[storeOffset+204:storeOffset+208], blockSize)
	binary.LittleEndian.PutUint32(data[storeOffset+208:storeOffset+212], writeCount)
	binary.LittleEndian.PutUint32(data[storeOffset+212:storeOffset+216], writeLength)
	binary.LittleEndian.PutUint32(data[storeOffset+216:storeOffset+220], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+220:storeOffset+224], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+224:storeOffset+228], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+228:storeOffset+232], 1)
	binary.LittleEndian.PutUint32(data[storeOffset+232:storeOffset+236], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+236:storeOffset+240], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 1)
	binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 1)
	return data
}

func fixtureAlignUp(value, alignment uint64) uint64 {
	if remainder := value % alignment; remainder != 0 {
		return value + alignment - remainder
	}
	return value
}
