package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	ffuAlgorithmSHA256       = uint32(0x0000800c)
	ffuHashReadBufferBytes   = 64 * 1024
	hashTableStructureSchema = 1
)

// HashTablePlan is a deterministic read-only description of the FFU catalog
// and chunk hash-table shape. It records source metadata digests but does not
// authenticate the catalog or compare any source chunk with a table entry.
type HashTablePlan struct {
	Schema                         int      `json:"schema"`
	SourceFileSize                 uint64   `json:"source_file_size"`
	AlgorithmID                    uint32   `json:"algorithm_id"`
	Algorithm                      string   `json:"algorithm"`
	DigestSizeBytes                uint32   `json:"digest_size_bytes"`
	CatalogOffset                  uint64   `json:"catalog_offset"`
	CatalogLength                  uint64   `json:"catalog_length"`
	CatalogSHA256                  string   `json:"catalog_sha256"`
	HashTableOffset                uint64   `json:"hash_table_offset"`
	HashTableLength                uint64   `json:"hash_table_length"`
	HashTableSHA256                string   `json:"hash_table_sha256"`
	HashEntryCount                 uint64   `json:"hash_entry_count"`
	HashTableShapeValidated        bool     `json:"hash_table_shape_validated"`
	CatalogAuthenticationAttempted bool     `json:"catalog_authentication_attempted"`
	HashTableCatalogAuthenticated  bool     `json:"hash_table_catalog_authenticated"`
	ContentVerificationAttempted   bool     `json:"content_verification_attempted"`
	ContentMatchesHashTable        bool     `json:"content_matches_hash_table"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Limitations                    []string `json:"limitations"`
}

// PlanHashTable re-inspects an FFU source and validates only the security
// algorithm and hash-table shape. Catalog and table bytes are streamed through
// SHA-256 for reproducible metadata recording; no signature or content claim is
// made by this function.
func PlanHashTable(ctx context.Context, reader io.ReaderAt, size uint64) (Inspection, HashTablePlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, errors.New("FFU hash-table context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, err
	}
	inspection, err := Inspect(reader, size)
	if err != nil {
		return Inspection{}, HashTablePlan{}, err
	}
	security := inspection.Security
	if security.AlgorithmID != ffuAlgorithmSHA256 {
		return inspection, HashTablePlan{}, fmt.Errorf("unsupported FFU hash algorithm 0x%08x: only CALG_SHA_256 (0x%08x) is accepted", security.AlgorithmID, ffuAlgorithmSHA256)
	}

	digestSize := uint64(sha256.Size)
	hashTableLength := uint64(security.HashTableSize)
	if hashTableLength == 0 || hashTableLength%digestSize != 0 {
		return inspection, HashTablePlan{}, fmt.Errorf("FFU hash table length %d is not a non-zero multiple of SHA-256 digest size %d", hashTableLength, digestSize)
	}
	hashEntryCount := hashTableLength / digestSize
	if hashEntryCount == 0 {
		return inspection, HashTablePlan{}, errors.New("FFU hash table contains no entries")
	}

	catalogLength := uint64(security.CatalogSize)
	if err := validateHashMetadataRegion(size, inspection.CatalogOffset, catalogLength, "catalog"); err != nil {
		return inspection, HashTablePlan{}, err
	}
	if err := validateHashMetadataRegion(size, inspection.HashTableOffset, hashTableLength, "hash table"); err != nil {
		return inspection, HashTablePlan{}, err
	}
	expectedHashTableOffset, err := checkedAdd(inspection.CatalogOffset, catalogLength)
	if err != nil || expectedHashTableOffset != inspection.HashTableOffset {
		return inspection, HashTablePlan{}, errors.New("FFU catalog and hash-table boundaries are inconsistent")
	}

	catalogDigest, err := hashFFURegion(ctx, reader, inspection.CatalogOffset, catalogLength)
	if err != nil {
		return inspection, HashTablePlan{}, fmt.Errorf("hash FFU catalog: %w", err)
	}
	hashTableDigest, err := hashFFURegion(ctx, reader, inspection.HashTableOffset, hashTableLength)
	if err != nil {
		return inspection, HashTablePlan{}, fmt.Errorf("hash FFU hash table: %w", err)
	}

	plan := HashTablePlan{
		Schema:                  hashTableStructureSchema,
		SourceFileSize:          size,
		AlgorithmID:             security.AlgorithmID,
		Algorithm:               "SHA-256",
		DigestSizeBytes:         uint32(digestSize),
		CatalogOffset:           inspection.CatalogOffset,
		CatalogLength:           catalogLength,
		CatalogSHA256:           catalogDigest,
		HashTableOffset:         inspection.HashTableOffset,
		HashTableLength:         hashTableLength,
		HashTableSHA256:         hashTableDigest,
		HashEntryCount:          hashEntryCount,
		HashTableShapeValidated: true,
		Limitations: []string{
			"the catalog digest is recorded but its CMS/PKCS#7 signature and trust chain are not authenticated",
			"hash entries are counted but are not compared with source chunks",
			"the first covered byte, chunk padding, final partial chunk, metadata coverage and trailing-byte rules remain unresolved",
			"no target is accepted and no regular-file, loop-device or physical-device executor exists",
		},
	}
	plan.PlanSHA256 = hashTablePlanDigest(plan)
	return inspection, plan, nil
}

func validateHashMetadataRegion(size, offset, length uint64, label string) error {
	end, err := checkedAdd(offset, length)
	if err != nil || length == 0 || offset > size || end > size {
		return fmt.Errorf("FFU %s range at offset %d with length %d exceeds source size %d", label, offset, length, size)
	}
	return nil
}

func hashFFURegion(ctx context.Context, reader io.ReaderAt, offset, length uint64) (string, error) {
	section := io.NewSectionReader(reader, int64(offset), int64(length))
	digest := sha256.New()
	buffer := make([]byte, ffuHashReadBufferBytes)
	copied, err := io.CopyBuffer(digest, &ffuContextReader{ctx: ctx, reader: section}, buffer)
	if err != nil {
		return "", err
	}
	if copied != int64(length) {
		return "", fmt.Errorf("read %d of %d bytes", copied, length)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type ffuContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *ffuContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if err == nil {
		if contextErr := reader.ctx.Err(); contextErr != nil {
			return count, contextErr
		}
	}
	return count, err
}

func hashTablePlanDigest(plan HashTablePlan) string {
	digest := sha256.New()
	writeHashPlanUint64(digest, uint64(plan.Schema))
	writeHashPlanUint64(digest, plan.SourceFileSize)
	writeHashPlanUint64(digest, uint64(plan.AlgorithmID))
	writeHashPlanString(digest, plan.Algorithm)
	writeHashPlanUint64(digest, uint64(plan.DigestSizeBytes))
	writeHashPlanUint64(digest, plan.CatalogOffset)
	writeHashPlanUint64(digest, plan.CatalogLength)
	writeHashPlanString(digest, plan.CatalogSHA256)
	writeHashPlanUint64(digest, plan.HashTableOffset)
	writeHashPlanUint64(digest, plan.HashTableLength)
	writeHashPlanString(digest, plan.HashTableSHA256)
	writeHashPlanUint64(digest, plan.HashEntryCount)
	writeHashPlanBool(digest, plan.HashTableShapeValidated)
	writeHashPlanBool(digest, plan.CatalogAuthenticationAttempted)
	writeHashPlanBool(digest, plan.HashTableCatalogAuthenticated)
	writeHashPlanBool(digest, plan.ContentVerificationAttempted)
	writeHashPlanBool(digest, plan.ContentMatchesHashTable)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeHashPlanUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeHashPlanString(digest hash.Hash, value string) {
	writeHashPlanUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeHashPlanBool(digest hash.Hash, value bool) {
	if value {
		writeHashPlanUint64(digest, 1)
		return
	}
	writeHashPlanUint64(digest, 0)
}
