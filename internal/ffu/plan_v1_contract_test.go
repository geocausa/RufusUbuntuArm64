package ffu

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPlanSingleStoreV1BindsSourceGeometry(t *testing.T) {
	data := validV1PlanFixture()
	_, plan, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceFileSize != uint64(len(data)) {
		t.Fatalf("source file size=%d want=%d", plan.SourceFileSize, len(data))
	}
	if plan.ChunkSizeBytes != 4096 || plan.BlockSizeBytes != 4096 {
		t.Fatalf("unexpected source geometry: chunk=%d block=%d", plan.ChunkSizeBytes, plan.BlockSizeBytes)
	}

	extended := append(append([]byte(nil), data...), make([]byte, 4096)...)
	_, extendedPlan, err := PlanSingleStoreV1(bytes.NewReader(extended), uint64(len(extended)))
	if err != nil {
		t.Fatal(err)
	}
	if extendedPlan.SourceFileSize != uint64(len(extended)) || extendedPlan.TrailingFileBytes != plan.TrailingFileBytes+4096 {
		t.Fatalf("extended source accounting is not bound: %#v", extendedPlan)
	}
	if extendedPlan.PlanSHA256 == plan.PlanSHA256 {
		t.Fatal("plan digest did not change when source size and trailing bytes changed")
	}
}

func TestPlanSingleStoreV1ValidatesGPTRangesInStableOrder(t *testing.T) {
	data := validV1PlanFixture()
	const storeOffset = 8192
	binary.LittleEndian.PutUint32(data[storeOffset+224:storeOffset+228], 10)
	binary.LittleEndian.PutUint32(data[storeOffset+228:storeOffset+232], 1)
	binary.LittleEndian.PutUint32(data[storeOffset+232:storeOffset+236], 20)
	binary.LittleEndian.PutUint32(data[storeOffset+236:storeOffset+240], 1)
	binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 30)
	binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 1)

	for attempt := 0; attempt < 20; attempt++ {
		_, _, err := PlanSingleStoreV1(bytes.NewReader(data), uint64(len(data)))
		if err == nil || !strings.Contains(err.Error(), "initial GPT table payload range") {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
	}
}
