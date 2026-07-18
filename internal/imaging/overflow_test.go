package imaging

import (
	"math"
	"testing"
)

func TestRoundedSectorCountDoesNotOverflowSignedSize(t *testing.T) {
	got := roundedSectorCount(math.MaxInt64, 512)
	want := uint64(math.MaxInt64/512) + 1
	if got != want {
		t.Fatalf("roundedSectorCount(MaxInt64, 512)=%d want %d", got, want)
	}
	if got := roundedSectorCount(1024, 512); got != 2 {
		t.Fatalf("roundedSectorCount(1024, 512)=%d want 2", got)
	}
	if got := roundedSectorCount(1025, 512); got != 3 {
		t.Fatalf("roundedSectorCount(1025, 512)=%d want 3", got)
	}
	for _, invalid := range [][2]int64{{0, 512}, {-1, 512}, {1, 0}, {1, -1}} {
		if got := roundedSectorCount(invalid[0], invalid[1]); got != 0 {
			t.Fatalf("roundedSectorCount(%d, %d)=%d want 0", invalid[0], invalid[1], got)
		}
	}
}
