package ffu

import (
	"errors"
	"fmt"
	"io"
)

const (
	calgSHA256          = uint32(0x0000800c)
	sha256DigestBytes   = uint32(32)
	maxHashTableEntries = uint64(1 << 27)
)

// HashTableShape describes the independently established security-catalog and
// hash-table regions. It does not authenticate the catalog, establish which
// source bytes each entry covers, or verify any content chunk.
type HashTableShape struct {
	Schema                        int    `json:"schema"`
	AlgorithmID                   uint32 `json:"algorithm_id"`
	AlgorithmName                 string `json:"algorithm_name"`
	DigestSizeBytes               uint32 `json:"digest_size_bytes"`
	HashEntryCount                uint64 `json:"hash_entry_count"`
	CatalogOffset                 uint64 `json:"catalog_offset"`
	CatalogLength                 uint64 `json:"catalog_length"`
	CatalogSHA256                 string `json:"catalog_sha256"`
	HashTableOffset               uint64 `json:"hash_table_offset"`
	HashTableLength               uint64 `json:"hash_table_length"`
	HashTableSHA256               string `json:"hash_table_sha256"`
	HashTableShapeValid           bool   `json:"hash_table_shape_valid"`
	ContentCoverageResolved       bool   `json:"content_coverage_resolved"`
	ContentMatchesHashTable       bool   `json:"content_matches_hash_table"`
	HashTableCatalogAuthenticated bool   `json:"hash_table_catalog_authenticated"`
	ExecutionSupported            bool   `json:"execution_supported"`
	Limitations                   []string `json:"limitations"`
}

// InspectHashTableShape validates the supported hash algorithm and table entry
// geometry, then fingerprints the catalog and table as read-only source
// regions. It deliberately performs no per-chunk comparison.
func InspectHashTableShape(reader io.ReaderAt, size uint64) (Inspection, HashTableShape, error) {
	inspection, err := Inspect(reader, size)
	if err != nil {
		return Inspection{}, HashTableShape{}, err
	}
	security := inspection.Security
	if security.AlgorithmID != calgSHA256 {
		return inspection, HashTableShape{}, fmt.Errorf(
			"unsupported FFU hash algorithm 0x%08x: only CALG_SHA_256 (0x%08x) is supported",
			security.AlgorithmID,
			calgSHA256,
		)
	}
	if security.HashTableSize == 0 {
		return inspection, HashTableShape{}, errors.New("FFU hash table is empty")
	}
	if security.HashTableSize%sha256DigestBytes != 0 {
		return inspection, HashTableShape{}, fmt.Errorf(
			"FFU SHA-256 hash table length %d is not a multiple of %d bytes",
			security.HashTableSize,
			sha256DigestBytes,
		)
	}
	entryCount := uint64(security.HashTableSize / sha256DigestBytes)
	if entryCount == 0 || entryCount > maxHashTableEntries {
		return inspection, HashTableShape{}, fmt.Errorf(
			"FFU hash entry count %d exceeds read-only structural limit %d",
			entryCount,
			maxHashTableEntries,
		)
	}

	catalogLength := uint64(security.CatalogSize)
	hashTableLength := uint64(security.HashTableSize)
	catalogDigest, err := hashRegion(reader, inspection.CatalogOffset, catalogLength)
	if err != nil {
		return inspection, HashTableShape{}, fmt.Errorf("fingerprint FFU security catalog: %w", err)
	}
	hashTableDigest, err := hashRegion(reader, inspection.HashTableOffset, hashTableLength)
	if err != nil {
		return inspection, HashTableShape{}, fmt.Errorf("fingerprint FFU hash table: %w", err)
	}

	return inspection, HashTableShape{
		Schema:                        1,
		AlgorithmID:                   security.AlgorithmID,
		AlgorithmName:                 "CALG_SHA_256",
		DigestSizeBytes:               sha256DigestBytes,
		HashEntryCount:                entryCount,
		CatalogOffset:                 inspection.CatalogOffset,
		CatalogLength:                 catalogLength,
		CatalogSHA256:                 catalogDigest,
		HashTableOffset:               inspection.HashTableOffset,
		HashTableLength:               hashTableLength,
		HashTableSHA256:               hashTableDigest,
		HashTableShapeValid:           true,
		ContentCoverageResolved:       false,
		ContentMatchesHashTable:       false,
		HashTableCatalogAuthenticated: false,
		ExecutionSupported:            false,
		Limitations: []string{
			"the catalog and hash table are fingerprinted but the catalog signature is not authenticated",
			"the first hashed byte and exact per-entry source coverage are not yet established",
			"no source content chunk is compared with a hash-table entry in this tranche",
			"a structurally valid unauthenticated hash table does not prove publisher authenticity",
			"no target is bound and no executor or device-writing path exists",
		},
	}, nil
}
