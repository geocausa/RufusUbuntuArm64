package imaging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCompressedContainerProgressReaderReportsBoundedMonotonicProgress(t *testing.T) {
	data := bytes.Repeat([]byte("progress"), 32*1024)
	var events []PrepareProgress
	reader := newCompressedContainerProgressReader(bytes.NewReader(data), uint64(len(data)), func(event PrepareProgress) {
		events = append(events, event)
	})
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		if event.Done == event.Total {
			t.Fatalf("event %d reported unauthenticated completion: %#v", i, event)
		}
	}
	reader.Complete()
	if len(events) < 2 {
		t.Fatalf("progress events=%d, want at least initial and authenticated final reports", len(events))
	}
	var previous uint64
	for i, event := range events {
		if event.Stage != "prepare_container" {
			t.Fatalf("event %d stage=%q", i, event.Stage)
		}
		if event.Total != uint64(len(data)) {
			t.Fatalf("event %d total=%d want %d", i, event.Total, len(data))
		}
		if event.Done < previous || event.Done > event.Total {
			t.Fatalf("event %d is not bounded and monotonic: previous=%d event=%#v", i, previous, event)
		}
		previous = event.Done
	}
	last := events[len(events)-1]
	if last.Done != last.Total {
		t.Fatalf("final event=%#v", last)
	}
}

func TestCompressedContainerProgressCompletesAfterAuthenticatedTrailingBytes(t *testing.T) {
	data := []byte("decoder-visible trailing-authenticated")
	var events []PrepareProgress
	reader := newCompressedContainerProgressReader(bytes.NewReader(data), uint64(len(data)), func(event PrepareProgress) {
		events = append(events, event)
	})
	buffer := make([]byte, 7)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Done >= events[len(events)-1].Total {
		t.Fatalf("pre-authentication event=%#v", events)
	}
	reader.Complete()
	last := events[len(events)-1]
	if last.Done != uint64(len(data)) || last.Total != uint64(len(data)) {
		t.Fatalf("completion event=%#v", last)
	}
}

func TestCompressedContainerProgressRejectsIdentityBoundOverrun(t *testing.T) {
	reader := newCompressedContainerProgressReader(bytes.NewReader([]byte("too-large")), 4, nil)
	buffer := make([]byte, 16)
	if _, err := reader.Read(buffer); err == nil {
		t.Fatal("reader accepted bytes beyond the identity-bound total")
	}
}

func TestSequentialCompressedPreparationReportsContainerAndExpandedTotals(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	var events []PrepareProgress
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(event PrepareProgress) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()

	var containerFinal, expandedFinal *PrepareProgress
	for i := range events {
		event := &events[i]
		if event.Stage == "prepare_container" && event.Done == event.Total && event.Total > 0 {
			containerFinal = event
		}
		if event.Stage == "prepare" && event.Done == uint64(len(raw)) && event.Total == uint64(len(raw)) {
			expandedFinal = event
		}
		if event.Stage == "prepare" && event.Done > 0 && event.Total == 0 {
			t.Fatalf("sequential compressed output emitted indeterminate positive progress: %#v", event)
		}
	}
	if containerFinal == nil {
		t.Fatalf("missing completed container progress in %#v", events)
	}
	if containerFinal.Total != uint64(identity.Size) {
		t.Fatalf("container total=%d want %d", containerFinal.Total, identity.Size)
	}
	if expandedFinal == nil {
		t.Fatalf("missing completed expanded-image progress in %#v", events)
	}
	opened, err := sourcefile.OpenRegular(prepared.Path, prepared.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSequentialCompressedPreparationHonorsCancellation(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a, 0xa5}, 4*1024*1024)
	path := filepath.Join(t.TempDir(), "cancel.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelledFromProgress := false
	prepared, err := PrepareInput(ctx, resolved, identity, func(event PrepareProgress) {
		if !cancelledFromProgress && event.Stage == "prepare_container" && event.Done > 0 {
			cancelledFromProgress = true
			cancel()
		}
	})
	if prepared != nil {
		prepared.Close()
		t.Fatal("cancelled preparation returned a prepared image")
	}
	if !cancelledFromProgress {
		t.Fatal("compressed container progress did not begin before cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled preparation error=%v", err)
	}
}
