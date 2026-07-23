package ffu

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestInspectVersion2Fixture(t *testing.T) {
	data := validFixture(t, 2)
	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Schema != 1 || inspection.RestorationSupported {
		t.Fatalf("unexpected inspection state: %#v", inspection)
	}
	if inspection.ImageHeaderOffset != 4096 || inspection.StoreHeaderOffset != 8192 || inspection.PayloadOffset != 12288 {
		t.Fatalf("unexpected offsets: image=%d store=%d payload=%d", inspection.ImageHeaderOffset, inspection.StoreHeaderOffset, inspection.PayloadOffset)
	}
	if inspection.Security.ChunkSizeBytes != 4096 || inspection.Store.BlockSizeBytes != 4096 {
		t.Fatalf("unexpected block geometry: %#v %#v", inspection.Security, inspection.Store)
	}
	if inspection.Store.PlatformID != "RufusArm64.Test" {
		t.Fatalf("platform ID=%q", inspection.Store.PlatformID)
	}
	if inspection.Store.CompressionAlgorithm != nil {
		t.Fatalf("version 2 unexpectedly has compression field: %v", *inspection.Store.CompressionAlgorithm)
	}
	if inspection.LogicalPayloadBytes != 8192 || inspection.PayloadFileBytes != 8192 {
		t.Fatalf("unexpected payload sizes: logical=%d file=%d", inspection.LogicalPayloadBytes, inspection.PayloadFileBytes)
	}
	if !inspection.IntegrityMetadataPresent || len(inspection.Limitations) == 0 {
		t.Fatalf("missing integrity/limitation reporting: %#v", inspection)
	}
}

func TestInspectVersion3Fixture(t *testing.T) {
	data := validFixture(t, 3)
	inspection, err := Inspect(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Store.HeaderSize != storeHeaderV3Bytes {
		t.Fatalf("store header size=%d", inspection.Store.HeaderSize)
	}
	if inspection.Store.CompressionAlgorithm == nil || *inspection.Store.CompressionAlgorithm != 3 {
		t.Fatalf("compression algorithm=%v", inspection.Store.CompressionAlgorithm)
	}
	if inspection.WriteDescriptorOffset != 8192+storeHeaderV3Bytes {
		t.Fatalf("write descriptor offset=%d", inspection.WriteDescriptorOffset)
	}
}

func TestInspectRejectsMalformedFixtures(t *testing.T) {
	valid := validFixture(t, 2)
	imageOffset := 4096
	storeOffset := 8192
	payloadOffset := 12288

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
			edit: func(data []byte) []byte { copy(data[4:16], "NotAnFFU!!!!"); return data },
			want: "invalid FFU security signature",
		},
		{
			name: "missing integrity metadata",
			edit: func(data []byte) []byte { binary.LittleEndian.PutUint32(data[28:32], 0); return data },
			want: "catalog and hash table",
		},
		{
			name: "bad image signature",
			edit: func(data []byte) []byte { copy(data[imageOffset+4:imageOffset+16], "NotImage!!!!"); return data },
			want: "invalid FFU image signature",
		},
		{
			name: "chunk mismatch",
			edit: func(data []byte) []byte { binary.LittleEndian.PutUint32(data[imageOffset+20:imageOffset+24], 8); return data },
			want: "chunk-size mismatch",
		},
		{
			name: "unsupported store version",
			edit: func(data []byte) []byte { binary.LittleEndian.PutUint16(data[storeOffset+8:storeOffset+10], 4); return data },
			want: "unsupported Full Flash format version",
		},
		{
			name: "invalid block size",
			edit: func(data []byte) []byte { binary.LittleEndian.PutUint32(data[storeOffset+204:storeOffset+208], 1000); return data },
			want: "invalid FFU block size",
		},
		{
			name: "short descriptor table",
			edit: func(data []byte) []byte { binary.LittleEndian.PutUint32(data[storeOffset+212:storeOffset+216], 31); return data },
			want: "write descriptor table is too short",
		},
		{
			name: "table range outside descriptors",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 2)
				binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 1)
				return data
			},
			want: "final table range",
		},
		{
			name: "payload beyond file",
			edit: func(data []byte) []byte { return data[:payloadOffset-1] },
			want: "payload starts",
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
	f.Add(validFixtureBytes(2))
	f.Add(validFixtureBytes(3))
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Inspect(bytes.NewReader(data), uint64(len(data)))
	})
}

func validFixture(t *testing.T, fullFlashMajor uint16) []byte {
	t.Helper()
	return validFixtureBytes(fullFlashMajor)
}

func validFixtureBytes(fullFlashMajor uint16) []byte {
	const (
		chunkKB       = uint32(4)
		chunkBytes    = 4096
		catalogSize   = uint32(16)
		hashTableSize = uint32(32)
		manifestSize  = uint32(17)
		imageOffset   = 4096
		storeOffset   = 8192
		payloadOffset = 12288
		blockSize     = uint32(4096)
		writeCount    = uint32(2)
	)

	storeBytes := uint32(storeHeaderV2Bytes)
	writeLength := uint32(32)
	if fullFlashMajor == 3 {
		storeBytes = storeHeaderV3Bytes
		writeLength = 40
	}
	data := make([]byte, payloadOffset+2*int(blockSize))

	binary.LittleEndian.PutUint32(data[0:4], securityHeaderBytes)
	copy(data[4:16], "SignedImage ")
	binary.LittleEndian.PutUint32(data[16:20], chunkKB)
	binary.LittleEndian.PutUint32(data[20:24], 0x800c)
	binary.LittleEndian.PutUint32(data[24:28], catalogSize)
	binary.LittleEndian.PutUint32(data[28:32], hashTableSize)
	for index := 0; index < int(catalogSize+hashTableSize); index++ {
		data[securityHeaderBytes+index] = byte(index + 1)
	}

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
	if fullFlashMajor == 3 {
		binary.LittleEndian.PutUint32(data[storeOffset+storeHeaderV2Bytes:storeOffset+int(storeBytes)], 3)
	}

	descriptorStart := storeOffset + int(storeBytes)
	for index := 0; index < int(writeLength); index++ {
		data[descriptorStart+index] = byte(index + 1)
	}
	for index := payloadOffset; index < len(data); index++ {
		data[index] = byte(index)
	}
	return data
}
