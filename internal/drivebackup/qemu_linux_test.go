//go:build linux

package drivebackup

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseContainerMeasureStrict(t *testing.T) {
	got, err := parseContainerMeasure([]byte(`{"required":4096,"fully-allocated":8192,"bitmaps":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.RequiredBytes != 4096 || got.FullyAllocatedBytes != 8192 {
		t.Fatalf("measure=%+v", got)
	}
	for _, data := range []string{
		`{"required":1,"required":2,"fully-allocated":2}`,
		`{"required":1,"fully-allocated":2,"unknown":0}`,
		`{"required":1.5,"fully-allocated":2}`,
		`{"required":3,"fully-allocated":2}`,
		`{"required":0,"fully-allocated":2}`,
		`{"required":1,"fully-allocated":2} {}`,
		`[]`,
	} {
		if _, err := parseContainerMeasure([]byte(data)); err == nil {
			t.Fatalf("malformed measure was accepted: %s", data)
		}
	}
}

func TestMeasureContainerUsesTrustedConservativePolicy(t *testing.T) {
	previous := resolveQEMUImg
	calls := 0
	resolveQEMUImg = func() (string, error) {
		calls++
		return "/usr/bin/qemu-img", nil
	}
	t.Cleanup(func() { resolveQEMUImg = previous })

	for _, test := range []struct {
		name       string
		sourceSize uint64
		want       uint64
	}{
		{
			name:       "minimum reserve",
			sourceSize: 8 * 1024 * 1024,
			want:       72 * 1024 * 1024,
		},
		{
			name:       "scaled reserve",
			sourceSize: 1024 * 1024 * 1024,
			want:       1152 * 1024 * 1024,
		},
		{
			name:       "rounded scaled reserve",
			sourceSize: 512*1024*1024 + 1,
			want:       576*1024*1024 + 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []Format{FormatVHD, FormatVHDX} {
				measure, err := MeasureContainer(context.Background(), test.sourceSize, format)
				if err != nil {
					t.Fatal(err)
				}
				if measure.RequiredBytes != 0 || measure.FullyAllocatedBytes != test.want {
					t.Fatalf("format=%s measure=%+v want fully allocated %d", format, measure, test.want)
				}
			}
		})
	}
	if calls != 6 {
		t.Fatalf("trusted resolver calls=%d want 6", calls)
	}
}

func TestMeasureContainerFailsClosed(t *testing.T) {
	previous := resolveQEMUImg
	t.Cleanup(func() { resolveQEMUImg = previous })
	resolveQEMUImg = func() (string, error) { return "", errors.New("unsafe utility") }
	if _, err := MeasureContainer(context.Background(), 1, FormatVHD); err == nil || !strings.Contains(err.Error(), "unsafe utility") {
		t.Fatalf("resolver error=%v", err)
	}
	if _, err := MeasureContainer(context.Background(), 1, FormatRaw); err == nil {
		t.Fatal("raw measurement succeeded")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MeasureContainer(cancelled, 1, FormatVHD); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled measurement error=%v", err)
	}

	resolveQEMUImg = func() (string, error) { return "/usr/bin/qemu-img", nil }
	if _, err := MeasureContainer(context.Background(), math.MaxUint64, FormatVHDX); err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("overflow error=%v", err)
	}
}

func TestBoundedCommandBufferRecordsOverflowWithoutShortWrite(t *testing.T) {
	buffer := newBoundedCommandBuffer(4)
	data := []byte("abcdefgh")
	n, err := buffer.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("write=%d,%v", n, err)
	}
	if !buffer.exceeded || string(buffer.Bytes()) != "abcd" {
		t.Fatalf("buffer exceeded=%t data=%q", buffer.exceeded, buffer.Bytes())
	}
}
