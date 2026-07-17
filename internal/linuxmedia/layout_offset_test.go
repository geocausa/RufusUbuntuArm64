//go:build linux

package linuxmedia

import (
	"math"
	"strings"
	"testing"
)

func TestPlanPersistentLayoutRejectsTargetBeyondSignedOffsetRange(t *testing.T) {
	_, err := PlanPersistentLayout(uint64(math.MaxInt64)+1, 512, 64*1024*1024, minimumPersistence, readyUbuntuDetection())
	if err == nil || !strings.Contains(err.Error(), "signed file-offset") {
		t.Fatalf("signed-offset error = %v", err)
	}
}

func TestWriteLayoutAtRejectsSignedOffsetOverflow(t *testing.T) {
	target := &memoryLayoutTarget{}
	if err := writeLayoutAt(target, []byte{1}, uint64(math.MaxInt64)+1); err == nil {
		t.Fatal("accepted an offset beyond MaxInt64")
	}
	if err := writeLayoutAt(target, []byte{1, 2}, uint64(math.MaxInt64)); err == nil {
		t.Fatal("accepted a write extent beyond MaxInt64")
	}
}

type memoryLayoutTarget struct{}

func (*memoryLayoutTarget) WriteAt(data []byte, offset int64) (int, error) { return len(data), nil }
func (*memoryLayoutTarget) ReadAt(data []byte, offset int64) (int, error)  { return len(data), nil }
func (*memoryLayoutTarget) Sync() error                                  { return nil }
