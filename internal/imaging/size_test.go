package imaging

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestCheckedImageAddRejectsOverflow(t *testing.T) {
	if got, err := checkedImageAdd("image", 4, 5); err != nil || got != 9 {
		t.Fatalf("checkedImageAdd normal result=%d err=%v", got, err)
	}
	if _, err := checkedImageAdd("image", math.MaxUint64, 1); err == nil || !strings.Contains(err.Error(), "64-bit") {
		t.Fatalf("checkedImageAdd overflow error=%v", err)
	}
}

func TestRequireHostFileSizeRejectsUnsignedOnlyRange(t *testing.T) {
	if err := requireHostFileSize("image", uint64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if err := requireHostFileSize("image", uint64(math.MaxInt64)+1); err == nil || !strings.Contains(err.Error(), "signed file-offset") {
		t.Fatalf("host-size error=%v", err)
	}
}

func TestSizeLimitWriterRejectsCounterOverflowBeforeWriting(t *testing.T) {
	var destination bytes.Buffer
	writer := &sizeLimitWriter{Writer: &destination, Written: math.MaxUint64 - 1}
	if n, err := writer.Write([]byte("ab")); n != 0 || err == nil || !writer.Exceeded {
		t.Fatalf("overflow write n=%d err=%v exceeded=%v", n, err, writer.Exceeded)
	}
	if destination.Len() != 0 {
		t.Fatalf("overflowing bytes were written: %q", destination.Bytes())
	}
}

func TestSizeLimitWriterWritesOnlyRemainingLimit(t *testing.T) {
	var destination bytes.Buffer
	writer := &sizeLimitWriter{Writer: &destination, Max: 3, Written: 2}
	if n, err := writer.Write([]byte("ab")); n != 1 || err == nil || !writer.Exceeded {
		t.Fatalf("limited write n=%d err=%v exceeded=%v", n, err, writer.Exceeded)
	}
	if got := destination.String(); got != "a" {
		t.Fatalf("limited output=%q want a", got)
	}
	if writer.Written != 3 {
		t.Fatalf("written counter=%d want 3", writer.Written)
	}
}
