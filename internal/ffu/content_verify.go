package ffu

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
	contentVerificationSchema = 1
	integrityDescriptorSchema = 1
)

// ContentVerification records a read-only comparison of every FFU hash-table
// entry with the corresponding source chunk. A matching result authenticates
// content only against the embedded table; it does not authenticate the table's
// catalog signature or publisher.
type ContentVerification struct {
	Schema                        int      `json:"schema"`
	SourceFileSize                uint64   `json:"source_file_size"`
	AlgorithmID                   uint32   `json:"algorithm_id"`
	Algorithm                     string   `json:"algorithm"`
	DigestSizeBytes               uint32   `json:"digest_size_bytes"`
	HashTableOffset               uint64   `json:"hash_table_offset"`
	HashTableLength               uint64   `json:"hash_table_length"`
	HashTableSHA256               string   `json:"hash_table_sha256"`
	HashEntryCount                uint64   `json:"hash_entry_count"`
	CoverageOffset                uint64   `json:"coverage_offset"`
	CoverageLength                uint64   `json:"coverage_length"`
	CoverageEnd                   uint64   `json:"coverage_end"`
	ChunkSizeBytes                uint64   `json:"chunk_size_bytes"`
	ExpectedChunkCount            uint64   `json:"expected_chunk_count"`
	VerifiedChunkCount            uint64   `json:"verified_chunk_count"`
	FinalChunkDataBytes           uint64   `json:"final_chunk_data_bytes"`
	FinalChunkZeroPaddingBytes    uint64   `json:"final_chunk_zero_padding_bytes"`
	ContentVerificationAttempted  bool     `json:"content_verification_attempted"`
	ContentMatchesHashTable       bool     `json:"content_matches_hash_table"`
	MismatchPresent               bool     `json:"mismatch_present"`
	MismatchEntryIndex            uint64   `json:"mismatch_entry_index"`
	MismatchSourceOffset          uint64   `json:"mismatch_source_offset"`
	MismatchExpectedSHA256        string   `json:"mismatch_expected_sha256"`
	MismatchActualSHA256          string   `json:"mismatch_actual_sha256"`
	HashTableCatalogAuthenticated bool     `json:"hash_table_catalog_authenticated"`
	IntegrityAuthenticated        bool     `json:"integrity_authenticated"`
	VerificationSHA256            string   `json:"verification_sha256"`
	Limitations                   []string `json:"limitations"`
}

// IntegrityDescriptorPlan binds the existing single-store-v1 descriptor plan to
// the structural hash-table plan and completed content comparison. It remains a
// read-only plan and never authorizes target access or execution.
type IntegrityDescriptorPlan struct {
	Schema                        int      `json:"schema"`
	SourceFileSize                uint64   `json:"source_file_size"`
	DescriptorPlanSHA256          string   `json:"descriptor_plan_sha256"`
	HashTablePlanSHA256           string   `json:"hash_table_plan_sha256"`
	ContentVerificationSHA256     string   `json:"content_verification_sha256"`
	HashTableSHA256               string   `json:"hash_table_sha256"`
	HashEntryCount                uint64   `json:"hash_entry_count"`
	CoverageOffset                uint64   `json:"coverage_offset"`
	CoverageLength                uint64   `json:"coverage_length"`
	CoverageEnd                   uint64   `json:"coverage_end"`
	ChunkSizeBytes                uint64   `json:"chunk_size_bytes"`
	VerifiedChunkCount            uint64   `json:"verified_chunk_count"`
	FinalChunkZeroPaddingBytes    uint64   `json:"final_chunk_zero_padding_bytes"`
	ContentVerificationAttempted  bool     `json:"content_verification_attempted"`
	ContentMatchesHashTable       bool     `json:"content_matches_hash_table"`
	HashTableCatalogAuthenticated bool     `json:"hash_table_catalog_authenticated"`
	IntegrityAuthenticated        bool     `json:"integrity_authenticated"`
	TargetSizeBindingRequired     bool     `json:"target_size_binding_required"`
	ExecutionSupported            bool     `json:"execution_supported"`
	PlanSHA256                    string   `json:"plan_sha256"`
	Limitations                   []string `json:"limitations"`
}

// VerifyHashTableContent re-inspects the source, validates the hash-table shape,
// and compares each SHA-256 entry with one chunk beginning at ImageHeaderOffset.
// A final partial chunk is zero-filled to the declared chunk size before hashing.
func VerifyHashTableContent(ctx context.Context, reader io.ReaderAt, size uint64) (Inspection, HashTablePlan, ContentVerification, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, ContentVerification{}, errors.New("FFU content-verification context is nil")
	}
	inspection, hashPlan, err := PlanHashTable(ctx, reader, size)
	if err != nil {
		return inspection, hashPlan, ContentVerification{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, hashPlan, ContentVerification{}, err
	}

	coverageOffset := inspection.ImageHeaderOffset
	if coverageOffset >= size {
		return inspection, hashPlan, ContentVerification{}, fmt.Errorf("FFU content coverage starts at %d outside source size %d", coverageOffset, size)
	}
	chunkSize := inspection.Security.ChunkSizeBytes
	if chunkSize == 0 {
		return inspection, hashPlan, ContentVerification{}, errors.New("FFU content verification has zero chunk size")
	}
	coverageLength := size - coverageOffset
	expectedChunks := coverageLength / chunkSize
	finalDataBytes := coverageLength % chunkSize
	if finalDataBytes != 0 {
		expectedChunks++
	} else {
		finalDataBytes = chunkSize
	}
	if expectedChunks == 0 {
		return inspection, hashPlan, ContentVerification{}, errors.New("FFU content coverage contains no chunks")
	}

	verification := ContentVerification{
		Schema:                        contentVerificationSchema,
		SourceFileSize:                size,
		AlgorithmID:                   inspection.Security.AlgorithmID,
		Algorithm:                     "SHA-256",
		DigestSizeBytes:               sha256.Size,
		HashTableOffset:               hashPlan.HashTableOffset,
		HashTableLength:               hashPlan.HashTableLength,
		HashTableSHA256:               hashPlan.HashTableSHA256,
		HashEntryCount:                hashPlan.HashEntryCount,
		CoverageOffset:                coverageOffset,
		CoverageLength:                coverageLength,
		CoverageEnd:                   size,
		ChunkSizeBytes:                chunkSize,
		ExpectedChunkCount:            expectedChunks,
		FinalChunkDataBytes:           finalDataBytes,
		FinalChunkZeroPaddingBytes:    chunkSize - finalDataBytes,
		HashTableCatalogAuthenticated: hashPlan.HashTableCatalogAuthenticated,
		Limitations: []string{
			"matching content proves consistency only with the embedded hash table",
			"the catalog CMS/PKCS#7 signature and trust chain are not authenticated",
			"no target is accepted and no regular-file, loop-device or physical-device executor exists",
		},
	}
	if hashPlan.HashEntryCount != expectedChunks {
		verification.VerificationSHA256 = contentVerificationDigest(verification)
		return inspection, hashPlan, verification, fmt.Errorf("FFU hash table has %d entries but source coverage requires exactly %d chunks", hashPlan.HashEntryCount, expectedChunks)
	}

	verification.ContentVerificationAttempted = true
	readBuffer := make([]byte, ffuHashReadBufferBytes)
	zeroBuffer := make([]byte, ffuHashReadBufferBytes)
	expectedDigest := make([]byte, sha256.Size)
	for index := uint64(0); index < expectedChunks; index++ {
		if err := ctx.Err(); err != nil {
			verification.VerificationSHA256 = contentVerificationDigest(verification)
			return inspection, hashPlan, verification, err
		}
		chunkDelta, err := checkedMul(index, chunkSize)
		if err != nil {
			return inspection, hashPlan, verification, errors.New("FFU content chunk offset overflows")
		}
		sourceOffset, err := checkedAdd(coverageOffset, chunkDelta)
		if err != nil {
			return inspection, hashPlan, verification, errors.New("FFU content source offset overflows")
		}
		dataLength := chunkSize
		if remaining := size - sourceOffset; remaining < dataLength {
			dataLength = remaining
		}
		actualDigest, err := hashFFUContentChunk(ctx, reader, sourceOffset, dataLength, chunkSize, readBuffer, zeroBuffer)
		if err != nil {
			verification.VerificationSHA256 = contentVerificationDigest(verification)
			return inspection, hashPlan, verification, fmt.Errorf("hash FFU content chunk %d at source offset %d: %w", index, sourceOffset, err)
		}
		tableDelta, err := checkedMul(index, uint64(sha256.Size))
		if err != nil {
			return inspection, hashPlan, verification, errors.New("FFU hash-table entry offset overflows")
		}
		entryOffset, err := checkedAdd(hashPlan.HashTableOffset, tableDelta)
		if err != nil {
			return inspection, hashPlan, verification, errors.New("FFU hash-table entry offset overflows")
		}
		if err := readExactFFUAt(reader, entryOffset, expectedDigest, fmt.Sprintf("hash-table entry %d", index)); err != nil {
			verification.VerificationSHA256 = contentVerificationDigest(verification)
			return inspection, hashPlan, verification, err
		}
		if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
			verification.MismatchPresent = true
			verification.MismatchEntryIndex = index
			verification.MismatchSourceOffset = sourceOffset
			verification.MismatchExpectedSHA256 = hex.EncodeToString(expectedDigest)
			verification.MismatchActualSHA256 = hex.EncodeToString(actualDigest)
			verification.VerificationSHA256 = contentVerificationDigest(verification)
			return inspection, hashPlan, verification, fmt.Errorf("FFU content chunk %d at source offset %d does not match its hash-table entry", index, sourceOffset)
		}
		verification.VerifiedChunkCount++
	}

	finalHashTableDigest, err := hashFFURegion(ctx, reader, hashPlan.HashTableOffset, hashPlan.HashTableLength)
	if err != nil {
		verification.VerificationSHA256 = contentVerificationDigest(verification)
		return inspection, hashPlan, verification, fmt.Errorf("rehash FFU hash table after content verification: %w", err)
	}
	if finalHashTableDigest != hashPlan.HashTableSHA256 {
		verification.VerificationSHA256 = contentVerificationDigest(verification)
		return inspection, hashPlan, verification, errors.New("FFU hash table changed while source content was being verified")
	}

	verification.ContentMatchesHashTable = true
	verification.IntegrityAuthenticated = verification.ContentMatchesHashTable && verification.HashTableCatalogAuthenticated
	verification.VerificationSHA256 = contentVerificationDigest(verification)
	return inspection, hashPlan, verification, nil
}

// PlanVerifiedSingleStoreV1 creates an outer deterministic plan that binds the
// descriptor map to the completed source-content comparison. Publisher trust and
// every target-side operation remain disabled.
func PlanVerifiedSingleStoreV1(ctx context.Context, reader io.ReaderAt, size uint64) (Inspection, DescriptorPlan, HashTablePlan, ContentVerification, IntegrityDescriptorPlan, error) {
	descriptorInspection, descriptorPlan, err := PlanSingleStoreV1(reader, size)
	if err != nil {
		return descriptorInspection, descriptorPlan, HashTablePlan{}, ContentVerification{}, IntegrityDescriptorPlan{}, err
	}
	hashInspection, hashPlan, verification, err := VerifyHashTableContent(ctx, reader, size)
	if err != nil {
		return hashInspection, descriptorPlan, hashPlan, verification, IntegrityDescriptorPlan{}, err
	}
	if descriptorInspection.ImageHeaderOffset != hashInspection.ImageHeaderOffset || descriptorPlan.SourceFileSize != verification.SourceFileSize || descriptorPlan.ChunkSizeBytes != verification.ChunkSizeBytes {
		return hashInspection, descriptorPlan, hashPlan, verification, IntegrityDescriptorPlan{}, errors.New("FFU descriptor and content-verification plans disagree on source geometry")
	}

	plan := IntegrityDescriptorPlan{
		Schema:                        integrityDescriptorSchema,
		SourceFileSize:                size,
		DescriptorPlanSHA256:          descriptorPlan.PlanSHA256,
		HashTablePlanSHA256:           hashPlan.PlanSHA256,
		ContentVerificationSHA256:     verification.VerificationSHA256,
		HashTableSHA256:               verification.HashTableSHA256,
		HashEntryCount:                verification.HashEntryCount,
		CoverageOffset:                verification.CoverageOffset,
		CoverageLength:                verification.CoverageLength,
		CoverageEnd:                   verification.CoverageEnd,
		ChunkSizeBytes:                verification.ChunkSizeBytes,
		VerifiedChunkCount:            verification.VerifiedChunkCount,
		FinalChunkZeroPaddingBytes:    verification.FinalChunkZeroPaddingBytes,
		ContentVerificationAttempted:  verification.ContentVerificationAttempted,
		ContentMatchesHashTable:       verification.ContentMatchesHashTable,
		HashTableCatalogAuthenticated: verification.HashTableCatalogAuthenticated,
		IntegrityAuthenticated:        verification.IntegrityAuthenticated,
		TargetSizeBindingRequired:     descriptorPlan.TargetSizeBindingRequired,
		ExecutionSupported:            false,
		Limitations: []string{
			"the descriptor map and source chunks are bound to an unauthenticated embedded hash table",
			"publisher authenticity remains false until an explicit catalog trust-root policy succeeds",
			"target identity, capacity, end-relative resolution, validation checks, writes, flush and readback are not implemented",
		},
	}
	plan.PlanSHA256 = integrityDescriptorPlanDigest(plan)
	return hashInspection, descriptorPlan, hashPlan, verification, plan, nil
}

func hashFFUContentChunk(ctx context.Context, reader io.ReaderAt, offset, dataLength, chunkSize uint64, readBuffer, zeroBuffer []byte) ([]byte, error) {
	if dataLength == 0 || dataLength > chunkSize {
		return nil, fmt.Errorf("invalid FFU content chunk data length %d for chunk size %d", dataLength, chunkSize)
	}
	section := io.NewSectionReader(reader, int64(offset), int64(dataLength))
	digest := sha256.New()
	copied, err := io.CopyBuffer(digest, &ffuContextReader{ctx: ctx, reader: section}, readBuffer)
	if err != nil {
		return nil, err
	}
	if copied != int64(dataLength) {
		return nil, fmt.Errorf("read %d of %d chunk bytes", copied, dataLength)
	}
	padding := chunkSize - dataLength
	for padding != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		writeLength := uint64(len(zeroBuffer))
		if padding < writeLength {
			writeLength = padding
		}
		if _, err := digest.Write(zeroBuffer[:int(writeLength)]); err != nil {
			return nil, err
		}
		padding -= writeLength
	}
	return digest.Sum(nil), nil
}

func readExactFFUAt(reader io.ReaderAt, offset uint64, buffer []byte, label string) error {
	count, err := reader.ReadAt(buffer, int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read FFU %s: %w", label, err)
	}
	if count != len(buffer) {
		return fmt.Errorf("truncated FFU %s at offset %d", label, offset)
	}
	return nil
}

func contentVerificationDigest(verification ContentVerification) string {
	digest := sha256.New()
	writeContentUint64(digest, uint64(verification.Schema))
	writeContentUint64(digest, verification.SourceFileSize)
	writeContentUint64(digest, uint64(verification.AlgorithmID))
	writeContentString(digest, verification.Algorithm)
	writeContentUint64(digest, uint64(verification.DigestSizeBytes))
	writeContentUint64(digest, verification.HashTableOffset)
	writeContentUint64(digest, verification.HashTableLength)
	writeContentString(digest, verification.HashTableSHA256)
	writeContentUint64(digest, verification.HashEntryCount)
	writeContentUint64(digest, verification.CoverageOffset)
	writeContentUint64(digest, verification.CoverageLength)
	writeContentUint64(digest, verification.CoverageEnd)
	writeContentUint64(digest, verification.ChunkSizeBytes)
	writeContentUint64(digest, verification.ExpectedChunkCount)
	writeContentUint64(digest, verification.VerifiedChunkCount)
	writeContentUint64(digest, verification.FinalChunkDataBytes)
	writeContentUint64(digest, verification.FinalChunkZeroPaddingBytes)
	writeContentBool(digest, verification.ContentVerificationAttempted)
	writeContentBool(digest, verification.ContentMatchesHashTable)
	writeContentBool(digest, verification.MismatchPresent)
	writeContentUint64(digest, verification.MismatchEntryIndex)
	writeContentUint64(digest, verification.MismatchSourceOffset)
	writeContentString(digest, verification.MismatchExpectedSHA256)
	writeContentString(digest, verification.MismatchActualSHA256)
	writeContentBool(digest, verification.HashTableCatalogAuthenticated)
	writeContentBool(digest, verification.IntegrityAuthenticated)
	return hex.EncodeToString(digest.Sum(nil))
}

func integrityDescriptorPlanDigest(plan IntegrityDescriptorPlan) string {
	digest := sha256.New()
	writeContentUint64(digest, uint64(plan.Schema))
	writeContentUint64(digest, plan.SourceFileSize)
	writeContentString(digest, plan.DescriptorPlanSHA256)
	writeContentString(digest, plan.HashTablePlanSHA256)
	writeContentString(digest, plan.ContentVerificationSHA256)
	writeContentString(digest, plan.HashTableSHA256)
	writeContentUint64(digest, plan.HashEntryCount)
	writeContentUint64(digest, plan.CoverageOffset)
	writeContentUint64(digest, plan.CoverageLength)
	writeContentUint64(digest, plan.CoverageEnd)
	writeContentUint64(digest, plan.ChunkSizeBytes)
	writeContentUint64(digest, plan.VerifiedChunkCount)
	writeContentUint64(digest, plan.FinalChunkZeroPaddingBytes)
	writeContentBool(digest, plan.ContentVerificationAttempted)
	writeContentBool(digest, plan.ContentMatchesHashTable)
	writeContentBool(digest, plan.HashTableCatalogAuthenticated)
	writeContentBool(digest, plan.IntegrityAuthenticated)
	writeContentBool(digest, plan.TargetSizeBindingRequired)
	writeContentBool(digest, plan.ExecutionSupported)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeContentUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeContentString(digest hash.Hash, value string) {
	writeContentUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeContentBool(digest hash.Hash, value bool) {
	if value {
		writeContentUint64(digest, 1)
		return
	}
	writeContentUint64(digest, 0)
}
