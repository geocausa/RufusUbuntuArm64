package imaging

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeZIPImage(t *testing.T, path string, raw []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	entry, err := archive.Create("disk.img")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestZIPPreparationReportsBoundedExpandedProgress(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.zip")
	writeZIPImage(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	var events []PrepareProgress
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(event PrepareProgress) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()

	foundFinal := false
	for _, event := range events {
		if event.Stage != "prepare" || event.Total == 0 {
			continue
		}
		if event.Done > event.Total {
			t.Fatalf("unbounded ZIP progress event: %#v", event)
		}
		if event.Done == uint64(len(raw)) && event.Total == uint64(len(raw)) {
			foundFinal = true
		}
	}
	if !foundFinal {
		t.Fatalf("missing authenticated expanded ZIP completion in %#v", events)
	}
}

func TestZIPPreparationHonorsCancellationDuringExpandedCopy(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a, 0xa5}, 6*1024*1024)
	path := filepath.Join(t.TempDir(), "cancel.zip")
	writeZIPImage(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelledFromProgress := false
	prepared, err := PrepareInput(ctx, resolved, identity, func(event PrepareProgress) {
		if !cancelledFromProgress && event.Stage == "prepare" && event.Done > 0 && event.Total == uint64(len(raw)) {
			cancelledFromProgress = true
			cancel()
		}
	})
	if prepared != nil {
		prepared.Close()
		t.Fatal("cancelled ZIP preparation returned a prepared image")
	}
	if !cancelledFromProgress {
		t.Fatal("ZIP expanded progress did not begin before cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ZIP preparation error=%v", err)
	}
}
