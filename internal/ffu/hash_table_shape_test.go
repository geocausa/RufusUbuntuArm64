package ffu

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestInspectHashTableShapeSHA256(t *testing.T) {
	data := validV1PlanFixture()
	inspection, shape, err := InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Security.AlgorithmID != calgSHA256 {
		t.Fatalf("algorithm=0x%08x", inspection.Security.AlgorithmID)
	}
	if shape.Schema != 1 || !shape.HashTableShapeValid {
		t.Fatalf("unexpected shape: %#v", shape)
	}
	if shape.AlgorithmName != "CALG_SHA_256" || shape.DigestSizeBytes != 32 || shape.HashEntryCount != 1 {
		t.Fatalf("unexpected algorithm geometry: %#v", shape)
	}
	if shape.CatalogOffset != 32 || shape.CatalogLength != 16 || shape.HashTableOffset != 48 || shape.HashTableLength != 32 {
		t.Fatalf("unexpected security regions: %#v", shape)
	}
	catalogDigest := sha256.Sum256(data[32:48])
	tableDigest := sha256.Sum256(data[48:80])
	if shape.CatalogSHA256 != hex.EncodeToString(catalogDigest[:]) {
		t.Fatalf("catalog digest=%q", shape.CatalogSHA256)
	}
	if shape.HashTableSHA256 != hex.EncodeToString(tableDigest[:]) {
		t.Fatalf("table digest=%q", shape.HashTableSHA256)
	}
	if shape.ContentCoverageResolved || shape.ContentMatchesHashTable || shape.HashTableCatalogAuthenticated || shape.ExecutionSupported {
		t.Fatalf("structural inspection overclaimed integrity: %#v", shape)
	}
	if len(shape.Limitations) == 0 {
		t.Fatal("missing structural limitations")
	}
}

func TestInspectHashTableShapeFingerprintsMutations(t *testing.T) {
	original := validV1PlanFixture()
	_, originalShape, err := InspectHashTableShape(bytes.NewReader(original), uint64(len(original)))
	if err != nil {
		t.Fatal(err)
	}

	catalogChanged := append([]byte(nil), original...)
	catalogChanged[32] ^= 0xff
	_, catalogShape, err := InspectHashTableShape(bytes.NewReader(catalogChanged), uint64(len(catalogChanged)))
	if err != nil {
		t.Fatal(err)
	}
	if catalogShape.CatalogSHA256 == originalShape.CatalogSHA256 || catalogShape.HashTableSHA256 != originalShape.HashTableSHA256 {
		t.Fatalf("catalog mutation was not isolated: original=%#v changed=%#v", originalShape, catalogShape)
	}

	tableChanged := append([]byte(nil), original...)
	tableChanged[48] ^= 0xff
	_, tableShape, err := InspectHashTableShape(bytes.NewReader(tableChanged), uint64(len(tableChanged)))
	if err != nil {
		t.Fatal(err)
	}
	if tableShape.HashTableSHA256 == originalShape.HashTableSHA256 || tableShape.CatalogSHA256 != originalShape.CatalogSHA256 {
		t.Fatalf("table mutation was not isolated: original=%#v changed=%#v", originalShape, tableShape)
	}
}

func TestInspectHashTableShapeRejectsUnsupportedAlgorithm(t *testing.T) {
	data := validV1PlanFixture()
	binary.LittleEndian.PutUint32(data[20:24], 0x0000800d)
	inspection, _, err := InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "only CALG_SHA_256") {
		t.Fatalf("error=%v", err)
	}
	if inspection.Security.AlgorithmID != 0x0000800d || inspection.RestorationSupported {
		t.Fatalf("unexpected common inspection: %#v", inspection)
	}
}

func TestInspectHashTableShapeRejectsMisalignedTableLength(t *testing.T) {
	data := validV1PlanFixture()
	binary.LittleEndian.PutUint32(data[28:32], 31)
	inspection, _, err := InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "not a multiple of 32 bytes") {
		t.Fatalf("error=%v", err)
	}
	if inspection.Security.HashTableSize != 31 || inspection.RestorationSupported {
		t.Fatalf("unexpected common inspection: %#v", inspection)
	}
}

func TestInspectHashTableShapeIsDeterministic(t *testing.T) {
	data := validV1PlanFixture()
	_, first, err := InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("shape changed between identical reads:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func FuzzInspectHashTableShapeDoesNotPanic(f *testing.F) {
	f.Add(validV1PlanFixture())
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = InspectHashTableShape(bytes.NewReader(data), uint64(len(data)))
	})
}
