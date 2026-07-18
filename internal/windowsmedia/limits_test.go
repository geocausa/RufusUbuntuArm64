//go:build linux

package windowsmedia

import (
	"math"
	"strings"
	"testing"
)

func TestCheckedAddRejectsOverflow(t *testing.T) {
	if got, err := checkedAdd("test total", 1, 2, 3); err != nil || got != 6 {
		t.Fatalf("checkedAdd normal result=%d err=%v", got, err)
	}
	if _, err := checkedAdd("test total", math.MaxUint64, 1); err == nil || !strings.Contains(err.Error(), "64-bit") {
		t.Fatalf("checkedAdd overflow error=%v", err)
	}
}

func TestCheckedMultiplyRejectsOverflow(t *testing.T) {
	if got, err := checkedMultiply("test product", 4, 8); err != nil || got != 32 {
		t.Fatalf("checkedMultiply normal result=%d err=%v", got, err)
	}
	if _, err := checkedMultiply("test product", math.MaxUint64, 2); err == nil || !strings.Contains(err.Error(), "64-bit") {
		t.Fatalf("checkedMultiply overflow error=%v", err)
	}
}

func TestCountBoundedEntryEnforcesExactLimit(t *testing.T) {
	count := 0
	if err := countBoundedEntry(&count, 2, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := countBoundedEntry(&count, 2, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := countBoundedEntry(&count, 2, "fixture"); err == nil || !strings.Contains(err.Error(), "more than 2") {
		t.Fatalf("entry-limit error=%v", err)
	}
	if err := countBoundedEntry(nil, 2, "fixture"); err == nil {
		t.Fatal("nil counter was accepted")
	}
}

func TestFinalizePlanUsesCheckedCapacityArithmetic(t *testing.T) {
	plan := mediaPlan{
		OtherBytes:         100,
		InstallSize:        200,
		DriverBytes:        300,
		DriverFolder:       "/drivers",
		Filesystem:         "fat32",
		AnswerFile:         []byte("new"),
		ExistingAnswerSize: 10,
	}
	if err := finalizePlan(&plan); err != nil {
		t.Fatal(err)
	}
	wantCopy := uint64(100 - 10 + len("new") + 200 + 300 + len(rufusDriverMarker))
	if plan.CopyBytes != wantCopy {
		t.Fatalf("CopyBytes=%d want %d", plan.CopyBytes, wantCopy)
	}
	if plan.RequiredBytes <= plan.CopyBytes {
		t.Fatalf("RequiredBytes=%d must exceed CopyBytes=%d", plan.RequiredBytes, plan.CopyBytes)
	}

	overflow := mediaPlan{OtherBytes: math.MaxUint64, InstallSize: 1, Filesystem: "fat32"}
	if err := finalizePlan(&overflow); err == nil || !strings.Contains(err.Error(), "64-bit") {
		t.Fatalf("finalize overflow error=%v", err)
	}

	invalidAnswer := mediaPlan{OtherBytes: 1, ExistingAnswerSize: 2, AnswerFile: []byte("replacement"), Filesystem: "fat32"}
	if err := finalizePlan(&invalidAnswer); err == nil || !strings.Contains(err.Error(), "answer file") {
		t.Fatalf("invalid answer-size error=%v", err)
	}
}
