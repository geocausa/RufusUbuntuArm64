package devicequal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBuildPlanQuickIsBoundedAndCoversEdges(t *testing.T) {
	const (
		regionSize = 4096
		capacity   = 100 * regionSize
	)
	plan, err := BuildPlan(capacity, regionSize, ProfileQuick)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Regions) != QuickRegionCount {
		t.Fatalf("got %d quick regions, want %d", len(plan.Regions), QuickRegionCount)
	}
	if plan.Regions[0].Offset != 0 {
		t.Fatalf("first offset = %d, want 0", plan.Regions[0].Offset)
	}
	last := plan.Regions[len(plan.Regions)-1]
	if last.Offset+last.Length != capacity {
		t.Fatalf("last region ends at %d, want %d", last.Offset+last.Length, capacity)
	}
	for index := 1; index < len(plan.Regions); index++ {
		if plan.Regions[index-1].Offset >= plan.Regions[index].Offset {
			t.Fatalf("regions are not strictly ordered at %d", index)
		}
	}
	if len(plan.SentinelIndices) != len(plan.Regions) {
		t.Fatalf("quick sentinel count = %d, want %d", len(plan.SentinelIndices), len(plan.Regions))
	}
}

func TestBuildPlanFullCoversCapacityExactly(t *testing.T) {
	const (
		regionSize = 4096
		capacity   = 3*regionSize + 123
	)
	plan, err := BuildPlan(capacity, regionSize, ProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Regions) != 4 {
		t.Fatalf("region count = %d, want 4", len(plan.Regions))
	}
	if plan.PlannedBytes != capacity {
		t.Fatalf("planned bytes = %d, want %d", plan.PlannedBytes, capacity)
	}
	if got := plan.Regions[3].Length; got != 123 {
		t.Fatalf("tail length = %d, want 123", got)
	}
	if len(plan.SentinelIndices) < 2 || plan.SentinelIndices[0] != 0 || plan.SentinelIndices[len(plan.SentinelIndices)-1] != 3 {
		t.Fatalf("unexpected full sentinels: %v", plan.SentinelIndices)
	}
}

func TestBuildPlanRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name       string
		capacity   uint64
		regionSize uint64
		profile    Profile
	}{
		{name: "zero capacity", capacity: 0, regionSize: 4096, profile: ProfileQuick},
		{name: "offset overflow", capacity: 1 << 63, regionSize: 4096, profile: ProfileQuick},
		{name: "excessive region", capacity: 4096, regionSize: 1 << 31, profile: ProfileQuick},
		{name: "too many regions", capacity: (MaxRegions + 1) * 4096, regionSize: 4096, profile: ProfileFull},
		{name: "profile", capacity: 4096, regionSize: 4096, profile: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildPlan(test.capacity, test.regionSize, test.profile); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFillPatternIsAddressDerivedAndChunkStable(t *testing.T) {
	pattern := Pattern{ID: "test", Seed: 42}
	whole := make([]byte, 257)
	FillPattern(whole, 5, pattern)
	chunked := make([]byte, len(whole))
	FillPattern(chunked[:73], 5, pattern)
	FillPattern(chunked[73:201], 5+73, pattern)
	FillPattern(chunked[201:], 5+201, pattern)
	if !reflect.DeepEqual(whole, chunked) {
		t.Fatal("pattern depends on chunk boundaries")
	}
	other := make([]byte, len(whole))
	FillPattern(other, 6, pattern)
	if reflect.DeepEqual(whole, other) {
		t.Fatal("pattern does not depend on absolute offset")
	}
}

func TestRunOrdinaryFilePassesAndReportsProgress(t *testing.T) {
	const (
		capacity   = 8 * 4096
		regionSize = 4096
	)
	path := filepath.Join(t.TempDir(), "qualification.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(capacity); err != nil {
		t.Fatal(err)
	}

	var progress []Progress
	now := steppingClock()
	report, err := Run(context.Background(), file, capacity, Config{
		Profile:    ProfileFull,
		RegionSize: regionSize,
		BufferSize: 4096,
		Patterns:   []Pattern{{ID: "address-test", Seed: 7}},
		Progress: func(event Progress) {
			progress = append(progress, event)
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusPassed || report.Failure != nil || report.AliasingDetected {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.CompletedBytes != 2*capacity {
		t.Fatalf("completed bytes = %d, want %d", report.CompletedBytes, 2*capacity)
	}
	if len(report.Passes) != 1 || report.Passes[0].WrittenBytes != capacity || report.Passes[0].VerifiedBytes != capacity {
		t.Fatalf("unexpected pass report: %+v", report.Passes)
	}
	if report.Passes[0].DurationMillis != 1000 || report.Passes[0].BytesPerSecond != 2*capacity {
		t.Fatalf("unexpected timing: %+v", report.Passes[0])
	}
	if len(progress) == 0 {
		t.Fatal("no progress events")
	}
	stages := map[string]bool{}
	for _, event := range progress {
		stages[event.Stage] = true
	}
	if !stages["write"] || !stages["verify"] {
		t.Fatalf("progress stages = %v", stages)
	}
}

func TestRunDetectsAliasedCapacity(t *testing.T) {
	const (
		regionSize      = 4096
		logicalCapacity = 8 * regionSize
		physicalSize    = 4 * regionSize
	)
	backend := newAliasingBackend(physicalSize)
	report, err := Run(context.Background(), backend, logicalCapacity, Config{
		Profile:    ProfileFull,
		RegionSize: regionSize,
		BufferSize: regionSize,
		Patterns:   []Pattern{{ID: "address-test", Seed: 11}},
		Now:        steppingClock(),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
	if report.Status != StatusFailed || !report.AliasingDetected {
		t.Fatalf("unexpected alias report: %+v", report)
	}
	if report.Failure == nil || report.Failure.Kind != "alias" {
		t.Fatalf("failure = %+v, want alias", report.Failure)
	}
	if report.Failure.AliasedWithOffset == nil {
		t.Fatal("alias owner offset is missing")
	}
	if *report.Failure.AliasedWithOffset == report.Failure.RegionOffset {
		t.Fatalf("alias owner %d equals failed region", *report.Failure.AliasedWithOffset)
	}
}

func TestRunReportsExactCorruptionOffset(t *testing.T) {
	const (
		regionSize = 4096
		capacity   = 4 * regionSize
	)
	backend := newAliasingBackend(capacity)
	backend.corruptOnSync = 123
	report, err := Run(context.Background(), backend, capacity, Config{
		Profile:    ProfileFull,
		RegionSize: regionSize,
		BufferSize: regionSize,
		Patterns:   []Pattern{{ID: "address-test", Seed: 13}},
		Now:        steppingClock(),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
	if report.Failure == nil || report.Failure.Kind != "mismatch" {
		t.Fatalf("failure = %+v, want mismatch", report.Failure)
	}
	if report.Failure.ByteOffset != 123 {
		t.Fatalf("byte offset = %d, want 123", report.Failure.ByteOffset)
	}
	if report.Failure.ExpectedSHA256 == "" || report.Failure.ActualSHA256 == "" || report.Failure.ExpectedSHA256 == report.Failure.ActualSHA256 {
		t.Fatalf("unexpected digests: %+v", report.Failure)
	}
}

func TestRunRejectsShortWrite(t *testing.T) {
	backend := newAliasingBackend(8192)
	backend.shortWrite = true
	report, err := Run(context.Background(), backend, 8192, Config{
		Profile:    ProfileFull,
		RegionSize: 4096,
		BufferSize: 4096,
		Patterns:   []Pattern{{ID: "address-test", Seed: 17}},
		Now:        steppingClock(),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
	if report.Failure == nil || report.Failure.Kind != "write" || !errors.Is(errors.New(report.Failure.Message), io.ErrShortWrite) {
		if report.Failure == nil || report.Failure.Kind != "write" || report.Failure.Message != io.ErrShortWrite.Error() {
			t.Fatalf("unexpected failure: %+v", report.Failure)
		}
	}
}

func TestRunCancellationBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := newAliasingBackend(8192)
	report, err := Run(ctx, backend, 8192, Config{
		Profile:    ProfileFull,
		RegionSize: 4096,
		BufferSize: 4096,
		Patterns:   []Pattern{{ID: "address-test", Seed: 19}},
		Now:        steppingClock(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if report.Status != StatusCancelled || report.CompletedBytes != 0 || backend.writeCalls != 0 {
		t.Fatalf("unexpected cancellation report: %+v, writes=%d", report, backend.writeCalls)
	}
}

func TestReportJSONIsStable(t *testing.T) {
	alias := uint64(4096)
	report := Report{
		Schema:           1,
		Profile:          ProfileQuick,
		Capacity:         8192,
		RegionSize:       4096,
		RegionCount:      2,
		SentinelCount:    2,
		PatternCount:     1,
		PlannedBytes:     8192,
		CompletedBytes:   16384,
		Status:           StatusFailed,
		AliasingDetected: true,
		Failure: &Failure{
			Kind:              "alias",
			RegionIndex:       0,
			AliasedWithOffset: &alias,
			Message:           "simulated",
		},
	}
	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("JSON is not stable:\n%s\n%s", first, second)
	}
	var decoded Report
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report, decoded) {
		t.Fatalf("round trip mismatch:\nwant %+v\ngot  %+v", report, decoded)
	}
}

func steppingClock() func() time.Time {
	current := time.Unix(1_700_000_000, 0).Add(-time.Second)
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}

type aliasingBackend struct {
	data          []byte
	shortWrite    bool
	shortRead     bool
	corruptOnSync int
	writeCalls    int
}

func newAliasingBackend(physicalSize int) *aliasingBackend {
	return &aliasingBackend{data: make([]byte, physicalSize), corruptOnSync: -1}
}

func (backend *aliasingBackend) WriteAt(source []byte, offset int64) (int, error) {
	backend.writeCalls++
	limit := len(source)
	if backend.shortWrite && limit > 0 {
		limit--
	}
	for index := 0; index < limit; index++ {
		backend.data[(int(offset)+index)%len(backend.data)] = source[index]
	}
	return limit, nil
}

func (backend *aliasingBackend) ReadAt(destination []byte, offset int64) (int, error) {
	limit := len(destination)
	if backend.shortRead && limit > 0 {
		limit--
	}
	for index := 0; index < limit; index++ {
		destination[index] = backend.data[(int(offset)+index)%len(backend.data)]
	}
	if limit != len(destination) {
		return limit, io.EOF
	}
	return limit, nil
}

func (backend *aliasingBackend) Sync() error {
	if backend.corruptOnSync >= 0 {
		backend.data[backend.corruptOnSync%len(backend.data)] ^= 0xff
		backend.corruptOnSync = -1
	}
	return nil
}
