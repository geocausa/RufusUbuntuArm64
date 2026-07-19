package devicequal

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestRunCancellationDuringWriteStaysCancelled(t *testing.T) {
	const (
		regionSize = 8192
		capacity   = 3 * regionSize
	)
	ctx, cancel := context.WithCancel(context.Background())
	backend := newAliasingBackend(capacity)
	report, err := Run(ctx, backend, capacity, Config{
		Profile:    ProfileFull,
		RegionSize: regionSize,
		BufferSize: 4096,
		Patterns:   []Pattern{{ID: "address-test", Seed: 23}},
		Progress: func(event Progress) {
			if event.Stage == "write" && event.Done == 4096 {
				cancel()
			}
		},
		Now: steppingClock(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if report.Status != StatusCancelled {
		t.Fatalf("status = %q, want %q", report.Status, StatusCancelled)
	}
	if report.Failure == nil || report.Failure.Kind != "cancelled" {
		t.Fatalf("failure = %+v, want cancelled", report.Failure)
	}
	if report.CompletedBytes != 4096 {
		t.Fatalf("completed bytes = %d, want 4096", report.CompletedBytes)
	}
	if backend.writeCalls != 1 {
		t.Fatalf("write calls = %d, want 1", backend.writeCalls)
	}
}

func TestRunProgressIsMonotonicWithinEachPhase(t *testing.T) {
	const (
		regionSize = 4096
		capacity   = 8 * regionSize
	)
	backend := newAliasingBackend(capacity)
	var events []Progress
	report, err := Run(context.Background(), backend, capacity, Config{
		Profile:    ProfileFull,
		RegionSize: regionSize,
		BufferSize: regionSize,
		Patterns:   []Pattern{{ID: "address-test", Seed: 29}},
		Progress: func(event Progress) {
			events = append(events, event)
		},
		Now: steppingClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusPassed {
		t.Fatalf("status = %q, want passed", report.Status)
	}

	last := map[string]uint64{}
	seen := map[string]bool{}
	for _, event := range events {
		if event.Total != capacity {
			t.Fatalf("%s total = %d, want %d", event.Stage, event.Total, capacity)
		}
		if seen[event.Stage] && event.Done <= last[event.Stage] {
			t.Fatalf("%s progress moved from %d to %d", event.Stage, last[event.Stage], event.Done)
		}
		seen[event.Stage] = true
		last[event.Stage] = event.Done
	}
	for _, stage := range []string{"write", "verify"} {
		if !seen[stage] {
			t.Fatalf("missing %s progress", stage)
		}
		if last[stage] != capacity {
			t.Fatalf("final %s progress = %d, want %d", stage, last[stage], capacity)
		}
	}
}

func TestRunRejectsShortRead(t *testing.T) {
	backend := newAliasingBackend(8192)
	backend.shortRead = true
	report, err := Run(context.Background(), backend, 8192, Config{
		Profile:    ProfileFull,
		RegionSize: 4096,
		BufferSize: 4096,
		Patterns:   []Pattern{{ID: "address-test", Seed: 31}},
		Now:        steppingClock(),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("error = %v, want ErrVerification", err)
	}
	if report.Failure == nil || report.Failure.Kind != "read" {
		t.Fatalf("failure = %+v, want read", report.Failure)
	}
	if report.Failure.Message != io.ErrUnexpectedEOF.Error() {
		t.Fatalf("message = %q, want %q", report.Failure.Message, io.ErrUnexpectedEOF.Error())
	}
}

func TestRunRejectsDuplicatePatternIdentifiers(t *testing.T) {
	backend := newAliasingBackend(4096)
	_, err := Run(context.Background(), backend, 4096, Config{
		Profile:    ProfileFull,
		RegionSize: 4096,
		BufferSize: 4096,
		Patterns: []Pattern{
			{ID: "duplicate", Seed: 1},
			{ID: "duplicate", Seed: 2},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate pattern error")
	}
}

func TestDefaultPatternsAreDistinctAndProfileSized(t *testing.T) {
	quick, err := DefaultPatterns(ProfileQuick)
	if err != nil {
		t.Fatal(err)
	}
	full, err := DefaultPatterns(ProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	if len(quick) != 2 || len(full) != 4 {
		t.Fatalf("pattern counts quick=%d full=%d, want 2 and 4", len(quick), len(full))
	}
	seen := map[string]bool{}
	for _, pattern := range full {
		if seen[pattern.ID] {
			t.Fatalf("duplicate default pattern %q", pattern.ID)
		}
		seen[pattern.ID] = true
	}
}
