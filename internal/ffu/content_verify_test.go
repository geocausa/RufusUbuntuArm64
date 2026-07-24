package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestVerifyHashTableContentAndBindDescriptorPlan(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)

	inspection, descriptor, hashPlan, verification, integrated, err := PlanVerifiedSingleStoreV1(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || descriptor.PayloadOffset != 12288 {
		t.Fatalf("unexpected source layout: inspection=%#v descriptor=%#v", inspection, descriptor)
	}
	if verification.CoverageOffset != 4096 || verification.CoverageLength != 24576 || verification.CoverageEnd != uint64(len(data)) {
		t.Fatalf("unexpected coverage: %#v", verification)
	}
	if verification.ExpectedChunkCount != 6 || verification.VerifiedChunkCount != 6 {
		t.Fatalf("unexpected chunk accounting: %#v", verification)
	}
	if verification.FinalChunkDataBytes != 4096 || verification.FinalChunkZeroPaddingBytes != 0 {
		t.Fatalf("unexpected final chunk: %#v", verification)
	}
	if !verification.ContentVerificationAttempted || !verification.ContentMatchesHashTable || verification.HashTableCatalogAuthenticated || verification.IntegrityAuthenticated {
		t.Fatalf("unexpected trust state: %#v", verification)
	}
	if hashPlan.HashEntryCount != 6 || integrated.HashEntryCount != 6 || integrated.VerifiedChunkCount != 6 {
		t.Fatalf("unexpected integrated counts: hash=%#v integrated=%#v", hashPlan, integrated)
	}
	if integrated.ExecutionSupported || integrated.IntegrityAuthenticated || !integrated.TargetSizeBindingRequired {
		t.Fatalf("unexpected integrated state: %#v", integrated)
	}
	if len(verification.VerificationSHA256) != 64 || len(integrated.PlanSHA256) != 64 {
		t.Fatalf("missing deterministic digests: verification=%q integrated=%q", verification.VerificationSHA256, integrated.PlanSHA256)
	}

	_, _, _, secondVerification, secondIntegrated, err := PlanVerifiedSingleStoreV1(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if secondVerification.VerificationSHA256 != verification.VerificationSHA256 || secondIntegrated.PlanSHA256 != integrated.PlanSHA256 {
		t.Fatalf("plan digest changed: verification %s/%s integrated %s/%s", verification.VerificationSHA256, secondVerification.VerificationSHA256, integrated.PlanSHA256, secondIntegrated.PlanSHA256)
	}
}

func TestVerifyHashTableContentZeroPadsFinalPartialChunk(t *testing.T) {
	data := append(validV1PlanFixture(), bytes.Repeat([]byte{0xa5}, 17)...)
	sealV1HashTable(t, data)

	_, _, verification, err := VerifyHashTableContent(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if verification.ExpectedChunkCount != 7 || verification.VerifiedChunkCount != 7 {
		t.Fatalf("unexpected chunk count: %#v", verification)
	}
	if verification.FinalChunkDataBytes != 17 || verification.FinalChunkZeroPaddingBytes != 4096-17 {
		t.Fatalf("unexpected final partial chunk: %#v", verification)
	}
	if !verification.ContentMatchesHashTable || verification.IntegrityAuthenticated {
		t.Fatalf("unexpected verification state: %#v", verification)
	}
}

func TestVerifyHashTableContentReportsMismatch(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	data[12288] ^= 0xff

	_, _, verification, err := VerifyHashTableContent(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "content chunk 2") {
		t.Fatalf("error=%v", err)
	}
	if !verification.ContentVerificationAttempted || verification.ContentMatchesHashTable || !verification.MismatchPresent {
		t.Fatalf("unexpected mismatch state: %#v", verification)
	}
	if verification.VerifiedChunkCount != 2 || verification.MismatchEntryIndex != 2 || verification.MismatchSourceOffset != 12288 {
		t.Fatalf("unexpected mismatch location: %#v", verification)
	}
	if len(verification.MismatchExpectedSHA256) != 64 || len(verification.MismatchActualSHA256) != 64 || verification.MismatchExpectedSHA256 == verification.MismatchActualSHA256 {
		t.Fatalf("unexpected mismatch digests: %#v", verification)
	}
}

func TestVerifyHashTableContentRejectsEntryCountMismatch(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries uint32
	}{
		{name: "missing", entries: 5},
		{name: "extra", entries: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validV1PlanFixture()
			sealV1HashTable(t, data)
			binary.LittleEndian.PutUint32(data[28:32], test.entries*sha256.Size)

			_, plan, verification, err := VerifyHashTableContent(context.Background(), bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), "requires exactly 6 chunks") {
				t.Fatalf("error=%v", err)
			}
			if plan.HashEntryCount != uint64(test.entries) || verification.ContentVerificationAttempted || verification.ContentMatchesHashTable {
				t.Fatalf("unexpected count-mismatch state: plan=%#v verification=%#v", plan, verification)
			}
		})
	}
}

func TestVerifyHashTableContentRejectsReorderedEntries(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	const tableOffset = securityHeaderBytes + 16
	first := append([]byte(nil), data[tableOffset:tableOffset+sha256.Size]...)
	copy(data[tableOffset:tableOffset+sha256.Size], data[tableOffset+sha256.Size:tableOffset+2*sha256.Size])
	copy(data[tableOffset+sha256.Size:tableOffset+2*sha256.Size], first)

	_, _, verification, err := VerifyHashTableContent(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "content chunk 0") {
		t.Fatalf("error=%v", err)
	}
	if !verification.MismatchPresent || verification.MismatchEntryIndex != 0 || verification.VerifiedChunkCount != 0 {
		t.Fatalf("unexpected reordered-entry result: %#v", verification)
	}
}

func TestVerifyHashTableContentBoundsReadRequests(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	reader := &maxReadAtReader{reader: bytes.NewReader(data)}

	_, _, verification, err := VerifyHashTableContent(context.Background(), reader, uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !verification.ContentMatchesHashTable {
		t.Fatalf("content did not verify: %#v", verification)
	}
	if reader.maximum > ffuHashReadBufferBytes {
		t.Fatalf("maximum ReadAt request=%d exceeds bound %d", reader.maximum, ffuHashReadBufferBytes)
	}
}

func TestVerifyHashTableContentHonoursCancellation(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelContentReader{reader: bytes.NewReader(data), cancel: cancel}

	_, _, verification, err := VerifyHashTableContent(ctx, reader, uint64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if !verification.ContentVerificationAttempted || verification.ContentMatchesHashTable {
		t.Fatalf("unexpected cancelled state: %#v", verification)
	}
}

func TestVerifyHashTableContentRejectsChangingHashTable(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	reader := &changingHashTableReader{
		reader:      bytes.NewReader(data),
		tableOffset: securityHeaderBytes + 16,
		tableLength: 6 * sha256.Size,
	}

	_, _, verification, err := VerifyHashTableContent(context.Background(), reader, uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "hash table changed") {
		t.Fatalf("error=%v", err)
	}
	if verification.ContentMatchesHashTable || verification.VerifiedChunkCount != 6 {
		t.Fatalf("unexpected changed-table state: %#v", verification)
	}
}

func TestVerifyHashTableContentRejectsNilContext(t *testing.T) {
	data := validV1PlanFixture()
	sealV1HashTable(t, data)
	var nilContext context.Context
	if _, _, _, err := VerifyHashTableContent(nilContext, bytes.NewReader(data), uint64(len(data))); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("error=%v", err)
	}
}

func FuzzVerifyHashTableContentDoesNotPanic(f *testing.F) {
	valid := validV1PlanFixture()
	sealV1HashTableFuzz(valid)
	f.Add(valid)
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = VerifyHashTableContent(context.Background(), bytes.NewReader(data), uint64(len(data)))
	})
}

func sealV1HashTable(t *testing.T, data []byte) {
	t.Helper()
	if len(data) < 4097 {
		t.Fatalf("fixture too small: %d", len(data))
	}
	sealV1HashTableFuzz(data)
}

func sealV1HashTableFuzz(data []byte) {
	const (
		imageOffset = 4096
		chunkSize   = 4096
		tableOffset = securityHeaderBytes + 16
	)
	if len(data) <= imageOffset {
		return
	}
	coverageLength := len(data) - imageOffset
	chunkCount := (coverageLength + chunkSize - 1) / chunkSize
	tableLength := chunkCount * sha256.Size
	if tableOffset+tableLength > imageOffset || len(data) < tableOffset+tableLength {
		return
	}
	binary.LittleEndian.PutUint32(data[28:32], uint32(tableLength))
	for index := 0; index < chunkCount; index++ {
		start := imageOffset + index*chunkSize
		end := start + chunkSize
		chunk := make([]byte, chunkSize)
		if end > len(data) {
			end = len(data)
		}
		copy(chunk, data[start:end])
		digest := sha256.Sum256(chunk)
		copy(data[tableOffset+index*sha256.Size:tableOffset+(index+1)*sha256.Size], digest[:])
	}
}

type maxReadAtReader struct {
	reader  io.ReaderAt
	maximum int
}

func (reader *maxReadAtReader) ReadAt(buffer []byte, offset int64) (int, error) {
	if len(buffer) > reader.maximum {
		reader.maximum = len(buffer)
	}
	return reader.reader.ReadAt(buffer, offset)
}

type cancelContentReader struct {
	reader io.ReaderAt
	cancel context.CancelFunc
	done   bool
}

func (reader *cancelContentReader) ReadAt(buffer []byte, offset int64) (int, error) {
	count, err := reader.reader.ReadAt(buffer, offset)
	if !reader.done && offset >= 4096 && len(buffer) >= 4096 {
		reader.done = true
		reader.cancel()
	}
	return count, err
}

type changingHashTableReader struct {
	reader      io.ReaderAt
	tableOffset int64
	tableLength int
	fullReads   int
}

func (reader *changingHashTableReader) ReadAt(buffer []byte, offset int64) (int, error) {
	count, err := reader.reader.ReadAt(buffer, offset)
	if offset == reader.tableOffset && len(buffer) == reader.tableLength {
		reader.fullReads++
		if reader.fullReads >= 2 && count > 0 {
			buffer[0] ^= 0xff
		}
	}
	return count, err
}
