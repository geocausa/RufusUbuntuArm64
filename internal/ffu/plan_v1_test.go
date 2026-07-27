package ffu

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPlanSingleStoreV1(t *testing.T) {
	data := validV1PlanFixture()
	inspection, plan, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Schema != 3 || inspection.Store.MajorVersion != 1 {
		t.Fatalf("unexpected inspection: %#v", inspection)
	}
	if plan.Schema != 1 || plan.ExecutionSupported || plan.IntegrityAuthenticated {
		t.Fatalf("unexpected plan state: %#v", plan)
	}
	if plan.ValidationDescriptorOffset != 8440 || plan.WriteDescriptorOffset != 8456 || plan.WriteDescriptorEnd != 8496 {
		t.Fatalf("unexpected descriptor offsets: %#v", plan)
	}
	if plan.PayloadOffset != 12288 || plan.PayloadLength != 12288 || plan.PayloadEnd != 24576 {
		t.Fatalf("unexpected payload layout: %#v", plan)
	}
	if plan.TotalPayloadBlocks != 3 || plan.TrailingFileBytes != 4096 {
		t.Fatalf("unexpected payload accounting: %#v", plan)
	}
	if plan.BeginningExtentBlocks != 5 || plan.EndingExtentBlocks != 1 || plan.MinimumTargetBlocks != 6 || plan.MinimumTargetBytes != 24576 {
		t.Fatalf("unexpected target geometry: %#v", plan)
	}
	if len(plan.ValidationDescriptors) != 1 || plan.ValidationDescriptors[0].CompareDataSHA256 != "94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2" {
		t.Fatalf("unexpected validation descriptors: %#v", plan.ValidationDescriptors)
	}
	if len(plan.WriteDescriptors) != 2 {
		t.Fatalf("write descriptor count=%d", len(plan.WriteDescriptors))
	}
	first := plan.WriteDescriptors[0]
	second := plan.WriteDescriptors[1]
	if first.BlockCount != 2 || first.PayloadOffset != 12288 || first.PayloadLength != 8192 || len(first.Locations) != 1 {
		t.Fatalf("unexpected first descriptor: %#v", first)
	}
	if second.BlockCount != 1 || second.PayloadOffset != 20480 || second.PayloadLength != 4096 || len(second.Locations) != 2 {
		t.Fatalf("unexpected second descriptor: %#v", second)
	}
	if second.Locations[0].Anchor != "begin" || second.Locations[1].Anchor != "end" {
		t.Fatalf("unexpected destination anchors: %#v", second.Locations)
	}
	if plan.InitialTable.BlockEnd != 1 || plan.FlashOnlyTable.BlockCount != 0 || plan.FinalTable.BlockEnd != 3 {
		t.Fatalf("unexpected GPT payload ranges: %#v %#v %#v", plan.InitialTable, plan.FlashOnlyTable, plan.FinalTable)
	}
	if plan.HasDestinationOverlap || len(plan.DestinationOverlaps) != 0 {
		t.Fatalf("unexpected overlap: %#v", plan.DestinationOverlaps)
	}
	if len(plan.PlanSHA256) != 64 {
		t.Fatalf("plan digest=%q", plan.PlanSHA256)
	}

	_, secondPlan, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if secondPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("plan digest changed: %s != %s", secondPlan.PlanSHA256, plan.PlanSHA256)
	}
}

func TestPlanSingleStoreV1ReportsSameAnchorOverlap(t *testing.T) {
	data := validV1PlanFixture()
	const secondDescriptorFirstLocationBlockIndex = 8484
	binary.LittleEndian.PutUint32(data[secondDescriptorFirstLocationBlockIndex:secondDescriptorFirstLocationBlockIndex+4], 1)

	_, plan, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasDestinationOverlap || len(plan.DestinationOverlaps) != 1 {
		t.Fatalf("overlap not reported: %#v", plan.DestinationOverlaps)
	}
	overlap := plan.DestinationOverlaps[0]
	if overlap.Anchor != "begin" || overlap.OverlapStartBlock != 1 || overlap.OverlapEndBlock != 2 {
		t.Fatalf("unexpected overlap: %#v", overlap)
	}
	if plan.ExecutionSupported {
		t.Fatal("overlapping plan unexpectedly executable")
	}
}

func TestPlanSingleStoreV1RejectsUnsupportedStoreVersion(t *testing.T) {
	data := validV1PlanFixture()
	binary.LittleEndian.PutUint16(data[8196:8198], 2)
	inspection, _, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "requires 1.0") {
		t.Fatalf("error=%v", err)
	}
	if inspection.Store.MajorVersion != 2 || inspection.RestorationSupported {
		t.Fatalf("unexpected common inspection: %#v", inspection)
	}
}

func TestPlanSingleStoreV1RejectsMalformedTables(t *testing.T) {
	valid := validV1PlanFixture()
	tests := []struct {
		name string
		edit func([]byte) []byte
		want string
	}{
		{
			name: "zero validation compare bytes",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8448:8452], 0)
				return data
			},
			want: "zero comparison bytes",
		},
		{
			name: "validation descriptor exceeds table",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8448:8452], 8)
				return data
			},
			want: "exceeds declared table boundary",
		},
		{
			name: "zero write blocks",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8460:8464], 0)
				return data
			},
			want: "zero locations or blocks",
		},
		{
			name: "unknown disk method",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8464:8468], 1)
				return data
			},
			want: "unsupported disk access method 1",
		},
		{
			name: "write table has unconsumed bytes",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8404:8408], 41)
				return append(data, 0)
			},
			want: "unconsumed bytes",
		},
		{
			name: "payload truncated",
			edit: func(data []byte) []byte { return data[:24575] },
			want: "beyond file size",
		},
		{
			name: "GPT payload range exceeds blocks",
			edit: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[8432:8436], 3)
				binary.LittleEndian.PutUint32(data[8436:8440], 1)
				return data
			},
			want: "final GPT table payload range",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			data = test.edit(data)
			_, _, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func FuzzPlanSingleStoreV1DoesNotPanic(f *testing.F) {
	f.Add(validV1PlanFixture())
	f.Add([]byte("not an FFU"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	})
}

func validV1PlanFixture() []byte {
	const (
		chunkKB       = uint32(4)
		catalogSize   = uint32(16)
		hashTableSize = uint32(32)
		manifestSize  = uint32(17)
		imageOffset   = 4096
		storeOffset   = 8192
		blockSize     = uint32(4096)
		validateCount = uint32(1)
		validateBytes = uint32(16)
		writeCount    = uint32(2)
		writeBytes    = uint32(40)
		payloadOffset = 12288
	)

	data := make([]byte, 28672)
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
	copy(data[imageOffset+imageHeaderBytes:imageOffset+imageHeaderBytes+int(manifestSize)], "<FFU plan test/>")

	binary.LittleEndian.PutUint32(data[storeOffset:storeOffset+4], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+4:storeOffset+6], 1)
	binary.LittleEndian.PutUint16(data[storeOffset+6:storeOffset+8], 0)
	binary.LittleEndian.PutUint16(data[storeOffset+8:storeOffset+10], 1)
	binary.LittleEndian.PutUint16(data[storeOffset+10:storeOffset+12], 0)
	copy(data[storeOffset+12:storeOffset+204], "RufusArm64.Plan.Test")
	binary.LittleEndian.PutUint32(data[storeOffset+204:storeOffset+208], blockSize)
	binary.LittleEndian.PutUint32(data[storeOffset+208:storeOffset+212], writeCount)
	binary.LittleEndian.PutUint32(data[storeOffset+212:storeOffset+216], writeBytes)
	binary.LittleEndian.PutUint32(data[storeOffset+216:storeOffset+220], validateCount)
	binary.LittleEndian.PutUint32(data[storeOffset+220:storeOffset+224], validateBytes)
	binary.LittleEndian.PutUint32(data[storeOffset+224:storeOffset+228], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+228:storeOffset+232], 1)
	binary.LittleEndian.PutUint32(data[storeOffset+232:storeOffset+236], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+236:storeOffset+240], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 2)
	binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 1)

	validationOffset := storeOffset + storeCommonHeaderBytes
	binary.LittleEndian.PutUint32(data[validationOffset:validationOffset+4], 1)
	binary.LittleEndian.PutUint32(data[validationOffset+4:validationOffset+8], 2)
	binary.LittleEndian.PutUint32(data[validationOffset+8:validationOffset+12], 4)
	copy(data[validationOffset+12:validationOffset+16], "TEST")

	writeOffset := validationOffset + int(validateBytes)
	binary.LittleEndian.PutUint32(data[writeOffset:writeOffset+4], 1)
	binary.LittleEndian.PutUint32(data[writeOffset+4:writeOffset+8], 2)
	binary.LittleEndian.PutUint32(data[writeOffset+8:writeOffset+12], diskAccessBegin)
	binary.LittleEndian.PutUint32(data[writeOffset+12:writeOffset+16], 0)

	second := writeOffset + 16
	binary.LittleEndian.PutUint32(data[second:second+4], 2)
	binary.LittleEndian.PutUint32(data[second+4:second+8], 1)
	binary.LittleEndian.PutUint32(data[second+8:second+12], diskAccessBegin)
	binary.LittleEndian.PutUint32(data[second+12:second+16], 4)
	binary.LittleEndian.PutUint32(data[second+16:second+20], diskAccessEnd)
	binary.LittleEndian.PutUint32(data[second+20:second+24], 0)

	for index := payloadOffset; index < payloadOffset+3*int(blockSize); index++ {
		data[index] = byte(index)
	}
	return data
}
