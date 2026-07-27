package freedos

import (
	"bytes"
	"testing"
)

func TestBuildMediaImageMatchesReviewedFixture(t *testing.T) {
	want, plan := buildTestMedia(t)
	got, err := BuildMediaImage(plan)
	if err != nil {
		t.Fatalf("build media: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("constructed FreeDOS media differs from the independently assembled reviewed fixture")
	}
}

func TestBuildMediaImageIsDeterministic(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildMediaImage(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildMediaImage(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical FreeDOS media plans produced different bytes")
	}
}

func TestBuildMediaImageRejectsInvalidPlan(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	plan.PartitionStartSector++
	if _, err := BuildMediaImage(plan); err == nil {
		t.Fatal("expected altered media plan to be rejected")
	}
}
