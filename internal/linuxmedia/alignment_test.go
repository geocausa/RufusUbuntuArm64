//go:build linux

package linuxmedia

import (
	"math"
	"strings"
	"testing"
)

func TestAlignLayoutCheckedBoundaries(t *testing.T) {
	largestAligned := uint64(math.MaxUint64) / layoutAlignment * layoutAlignment
	for _, test := range []struct {
		name  string
		value uint64
		want  uint64
	}{
		{name: "zero", value: 0, want: 0},
		{name: "exact", value: 3 * layoutAlignment, want: 3 * layoutAlignment},
		{name: "round up", value: 3*layoutAlignment + 1, want: 4 * layoutAlignment},
		{name: "largest aligned", value: largestAligned, want: largestAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := alignLayoutChecked(test.value, layoutAlignment)
			if err != nil || got != test.want {
				t.Fatalf("align(%d) = %d, %v; want %d", test.value, got, err, test.want)
			}
		})
	}
	if _, err := alignLayoutChecked(largestAligned+1, layoutAlignment); err == nil {
		t.Fatal("alignment overflow was accepted")
	}
}

func TestPlanPersistentLayoutRejectsBootSizeAlignmentOverflow(t *testing.T) {
	largestAligned := uint64(math.MaxUint64) / layoutAlignment * layoutAlignment
	desiredTotal := largestAligned + 1
	candidate := desiredTotal - desiredTotal/21
	var copiedBytes uint64
	for offset := int64(-64); offset <= 64; offset++ {
		value := candidate
		if offset < 0 {
			value -= uint64(-offset)
		} else {
			value += uint64(offset)
		}
		if value <= math.MaxUint64-value/20 && value+value/20 == desiredTotal {
			copiedBytes = value
			break
		}
	}
	if copiedBytes == 0 {
		t.Fatal("test could not construct a non-overflowing media-plus-margin total")
	}

	_, err := PlanPersistentLayout(8*1024*1024*1024, 512, copiedBytes, 0, readyUbuntuDetection())
	if err == nil || !strings.Contains(err.Error(), "alignment overflows") {
		t.Fatalf("boot-size alignment overflow error = %v", err)
	}
}
