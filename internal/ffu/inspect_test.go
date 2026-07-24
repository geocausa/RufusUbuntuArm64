package ffu

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestInspectCommonStorePrefix(t *testing.T) {
	data := validFixtureBytes(2)
	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Schema != 3 || inspection.RestorationSupported {
		t.Fatalf("unexpected inspection state: %#v", inspection)
	}
	if inspection.ImageHeaderOffset != 4096 || inspection.StoreHeaderOffset != 8192 {
		t.Fatalf("unexpected offsets: image=%d store=%d", inspection.ImageHeaderOffset, inspection.StoreHeaderOffset)
	}
	if inspection.StoreCommonEndOffset != 8192+storeCommonHeaderBytes {
		t.Fatalf("common store end=%d", inspection.StoreCommonEndOffset)
	}
	if inspection.DescriptorLayoutResolved || inspection.PayloadLayoutResolved {
		t.Fatalf("variable layout unexpectedly resolved: %#v", inspection)
	}
	if inspection.MinimumDescriptorBytes != 32 {
		t.Fatalf("minimum descriptor bytes=%d", inspection.MinimumDescriptorBytes)
	}
	if inspection.Store.CommonHeaderSize != storeCommonHeaderBytes || inspection.Store.PlatformID != "RufusArm64.Test" {
		t.Fatalf("unexpected store metadata: %#v", inspection.Store)
	}
	if inspection.Security.ChunkSizeBytes != 4096 || inspection.Store.BlockSizeBytes != 4096 {
		t.Fatalf("unexpected geometry: %#v %#v", inspection.Security, inspection.Store)
	}
	if inspection.Store.InitialTableBlockEnd != 1 || inspection.Store.FinalTableBlockEnd != 2 {
		t.Fatalf("unexpected payload table ranges: %#v", inspection.Store)
	}
	if !inspection.IntegrityMetadataPresent || len(inspection.Limitations) == 0 {
		t.Fatalf("missing integrity/limitation reporting: %#v", inspection)
	}
}

func TestInspectTreatsGPTTablesAsPayloadBlockRanges(t *testing.T) {
	data := validFixtureBytes(2)
	const storeOffset = 8192
	binary.LittleEndian.PutUint32(data[storeOffset+224:storeOffset+228], 100)
	binary.LittleEndian.PutUint32(data[storeOffset+228:storeOffset+232], 7)
	binary.LittleEndian.PutUint32(data[storeOffset+232:storeOffset+236], 200)
	binary.LittleEndian.PutUint32(data[storeOffset+236:storeOffset+240], 11)
	binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 300)
	binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 13)

	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	store := inspection.Store
	if store.InitialTableBlockEnd != 107 || store.FlashOnlyTableBlockEnd != 211 || store.FinalTableBlockEnd != 313 {
		t.Fatalf("payload table ranges were compared with descriptor count: %#v", store)
	}
	if store.WriteDescriptorCount != 2 {
		t.Fatalf("write descriptor count=%d", store.WriteDescriptorCount)
	}
}

func TestInspectDoesNotGuessVariableStoreExtension(t *testing.T) {
	data := validFixtureBytes(2)
	storeCommonEnd := 8192 + storeCommonHeaderBytes
	copy(data[storeCommonEnd:storeCommonEnd+24], []byte("MULTISTORE-EXTENSION-DATA"))
	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.StoreCommonEndOffset != uint64(storeCommonEnd) {
		t.Fatalf("common end=%d", inspection.StoreCommonEndOffset)
	}
	if inspection.DescriptorLayoutResolved || inspection.PayloadLayoutResolved {
		t.Fatal("extension bytes were incorrectly interpreted as resolved layout")
	}
	if inspection.BytesAfterStoreCommon != uint64(len(data)-storeCommonEnd) {
		t.Fatalf("bytes after common=%d", inspection.BytesAfterStoreCommon)
	}
}

func TestInspectRecordsVersionWithoutAssumingLayout(t *testing.T) {
	data := validFixtureBytes(99)
	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Store.FullFlashMajorVersion != 99 {
		t.Fatalf("version=%d", inspection.Store.FullFlashMajorVersion)
	}
	if inspection.DescriptorLayoutResolved || inspection.PayloadLayoutResolved || inspection.RestorationSupported {
		t.Fatalf("unknown version produced a usable layout: %#v", inspection)
	}
}

func TestInspectRejectsMalformedFixtures(t *testing.T) {
	valid := validFixtureBytes(2)
	imageOffset := 4096
	storeOffset := 8192

	tests := []struct {
		name string
		edit func([]byte) []byte
		want string
	}{
		{
			name: "truncated security header",
			edit: func(data []byte) []byte { return data[:31] },
			want: "truncated FFU security header",
		},
		{
			name: "bad security signature",
			edit: func(data []byte) []byte {
				copy(data[4:16], "NotAnFFU!!!!")
				return data
			},
			want: "invalid FFU security signature",
		},
		{
			name: "missing integrity metadata",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[28:32], 0)
				return data
			},
			want: "catalog and hash table",
		},
		{
			name: "bad image signature",
			edit: func(data []byte) []byte {
				copy(data[imageOffset+4:imageOffset+16], "NotImage!!!!")
				return data
			},
			want: "invalid FFU image signature",
		},
		{
			name: "chunk mismatch",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[imageOffset+20:imageOffset+24], 8)
				return data
			},
			want: "chunk-size mismatch",
		},
		{
			name: "truncated common store prefix",
			edit: func(data []byte) []byte { return data[:storeOffset+storeCommonHeaderBytes-1] },
			want: "truncated FFU common store header",
		},
		{
			name: "invalid block size",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[storeOffset+204:storeOffset+208], 1000)
				return data
			},
			want: "invalid FFU block size",
		},
		{
			name: "short descriptor table",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[storeOffset+212:storeOffset+216], 31)
				return data
			},
			want: "write descriptor table is too short",
		},
		{
			name: "declared descriptors exceed tail",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[storeOffset+212:storeOffset+216], uint32(len(data)))
				return data
			},
			want: "too short to contain its declared descriptor tables",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			data = test.edit(data)
			_, err := Inspect(bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestInspectRejectsNilAndEmptyInputs(t *testing.T) {
	if _, err := Inspect(nil, 1); err == nil {
		t.Fatal("nil reader unexpectedly accepted")
	}
	if _, err := Inspect(bytes.NewReader(nil), 0); err == nil {
		t.Fatal("empty image unexpectedly accepted")
	}
}

func FuzzInspectDoesNotPanic(f *testing.F) {
	f.Add(validFixtureBytes(1))
	f.Add(validFixtureBytes(2))
	f.Add(validFixtureBytes(99))
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Inspect(bytes.NewReader(data), uint64(len(data)))
	})
}

func validFixtureBytes(fullFlashMajor uint16) []byte {
	const (
		chunkKB       = uint32(4)
		catalogSize   = uint32(16)
		hashTableSize = uint32(32)
		manifestSize  = uint32(17)
		imageOffset   = 4096
		storeOffset   = 8192
		blockSize     = uint32(4096)
		writeCount    = uint32(2)
		writeLength   = uint32(32)
	)

	data := make([]byte, 16384)
	binary.LittleEndian.PutUint32(data[0:4], securityHeaderBytes)
	copy(data[4:16], "SignedImage ")
	binary.LittleEndian.PutUint32(data[16:20], chunkKB)
	binary.LittleEndian.PutUint32(data[20:24], 0x800c)
	binary.LittleEndian.PutUint32(data[24:28], catalogSize)
	binary.LittleEndian.PutUint32(data[28:32], hashTableSize)

	binary.LittleEndian.PutUint32(data[imageOffset:imageOffset+4], imageHeaderBytes)
	copy(data[imageOffset+4:imageOffset+16], "ImageFlash  ")
	binary.LittleEndian.PutUint32(data[imageOffset+16:imageOffset+20], manifestSize)
	binary.LittleEndian.PutUint32(data[imageOffset+20:imageOffset+24], chunkKB)
	copy(data[imageOffset+imageHeaderBytes:imageOffset+imageHeaderBytes+int(manifestSize)], "<FFU test data/>")

	binary.LittleEndian.PutUint32(data[storeOffset:storeOffset+4], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+4:storeOffset+6], 1)
	binary.LittleEndian.PutUint16(data[storeOffset+6:storeOffset+8], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+8:storeOffset+10], fullFlashMajor)
	binary.LittleEndian.PutUint16(data[storeOffset+10:storeOffset+12], 0)
	copy(data[storeOffset+12:storeOffset+204], "RufusArm64.Test")
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
