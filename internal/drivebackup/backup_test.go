package drivebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureCopiesExactBytesAndHashes(t *testing.T) {
	data := bytes.Repeat([]byte("rufusarm64-backup\n"), 257)
	output := filepath.Join(t.TempDir(), "drive.img")
	var progress []Progress
	report, err := Capture(context.Background(), bytes.NewReader(data), output, uint64(len(data)), Config{
		BufferSize: 137,
		Progress: func(value Progress) {
			progress = append(progress, value)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusPassed || report.Schema != ReportSchema {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.CompletedBytes != uint64(len(data)) || report.PlannedBytes != uint64(len(data)) {
		t.Fatalf("unexpected byte accounting: %+v", report)
	}
	expectedHash := sha256.Sum256(data)
	if report.SHA256 != hex.EncodeToString(expectedHash[:]) {
		t.Fatalf("sha256 = %q, want %x", report.SHA256, expectedHash)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, data) {
		t.Fatal("captured image differs from source")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if len(progress) < 2 || progress[0] != (Progress{Done: 0, Total: uint64(len(data))}) {
		t.Fatalf("unexpected initial progress: %+v", progress)
	}
	last := uint64(0)
	for _, value := range progress {
		if value.Total != uint64(len(data)) || value.Done < last || value.Done > value.Total {
			t.Fatalf("invalid progress sequence: %+v", progress)
		}
		last = value.Done
	}
	if last != uint64(len(data)) {
		t.Fatalf("final progress = %d, want %d", last, len(data))
	}
}

func TestCaptureRefusesExistingDestinationWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "existing.img")
	original := []byte("keep this file")
	if err := os.WriteFile(output, original, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Capture(context.Background(), bytes.NewReader([]byte("source")), output, 6, Config{})
	if err == nil || report.Status != StatusFailed || report.Failure == nil || report.Failure.Kind != "open_destination" {
		t.Fatalf("unexpected result: report=%+v err=%v", report, err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing destination changed: %q", got)
	}
}

func TestCaptureRefusesSymlinkDestination(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "drive.img")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(context.Background(), bytes.NewReader([]byte("source")), link, 6, Config{}); err == nil {
		t.Fatal("symbolic-link destination was accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "target-data" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestCaptureRemovesIncompleteDestinationOnSourceTruncation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "truncated.img")
	report, err := Capture(context.Background(), bytes.NewReader([]byte("short")), output, 32, Config{BufferSize: 4})
	if err == nil || report.Status != StatusFailed || report.Failure == nil || report.Failure.Kind != "source_read" {
		t.Fatalf("unexpected result: report=%+v err=%v", report, err)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("incomplete destination remains: %v", statErr)
	}
}

func TestCaptureCancellationRemovesIncompleteDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	output := filepath.Join(t.TempDir(), "cancelled.img")
	report, err := Capture(ctx, bytes.NewReader([]byte("abcdefgh")), output, 8, Config{
		BufferSize: 4,
		Progress: func(progress Progress) {
			if progress.Done == 4 {
				cancel()
			}
		},
	})
	if !errors.Is(err, context.Canceled) || report.Status != StatusCancelled {
		t.Fatalf("unexpected cancellation: report=%+v err=%v", report, err)
	}
	if report.CompletedBytes != 4 || report.Failure == nil || report.Failure.ByteOffset == nil || *report.Failure.ByteOffset != 4 {
		t.Fatalf("unexpected cancellation report: %+v", report)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cancelled destination remains: %v", statErr)
	}
}

func TestCopyRecoversFromShortWrites(t *testing.T) {
	data := []byte("short writes are allowed when progress is made")
	destination := &recordingSyncWriter{maxWrite: 3}
	report, err := Copy(context.Background(), bytes.NewReader(data), destination, uint64(len(data)), Config{BufferSize: 11})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusPassed || !destination.synced || !bytes.Equal(destination.buffer.Bytes(), data) {
		t.Fatalf("unexpected copy: report=%+v destination=%+v", report, destination)
	}
}

func TestCopyClassifiesDestinationFailures(t *testing.T) {
	data := []byte("destination failure")
	for _, test := range []struct {
		name        string
		destination *recordingSyncWriter
		kind        string
	}{
		{name: "zero write", destination: &recordingSyncWriter{zeroWrite: true}, kind: "destination_write"},
		{name: "write error", destination: &recordingSyncWriter{writeErr: errors.New("write failed")}, kind: "destination_write"},
		{name: "invalid count", destination: &recordingSyncWriter{invalidCount: true}, kind: "destination_write"},
		{name: "sync error", destination: &recordingSyncWriter{syncErr: errors.New("sync failed")}, kind: "sync_destination"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Copy(context.Background(), bytes.NewReader(data), test.destination, uint64(len(data)), Config{BufferSize: 5})
			if err == nil || report.Status != StatusFailed || report.Failure == nil || report.Failure.Kind != test.kind {
				t.Fatalf("unexpected result: report=%+v err=%v", report, err)
			}
			if report.SHA256 != "" {
				t.Fatalf("failed report exposed a completed hash: %+v", report)
			}
		})
	}
}

func TestCopyValidationFailsClosed(t *testing.T) {
	validSource := bytes.NewReader([]byte("source"))
	validDestination := &recordingSyncWriter{}
	for _, test := range []struct {
		name        string
		source      io.ReaderAt
		destination syncWriter
		size        uint64
		config      Config
	}{
		{name: "nil source", destination: validDestination, size: 1},
		{name: "nil destination", source: validSource, size: 1},
		{name: "zero size", source: validSource, destination: validDestination},
		{name: "negative buffer", source: validSource, destination: validDestination, size: 1, config: Config{BufferSize: -1}},
		{name: "oversized buffer", source: validSource, destination: validDestination, size: 1, config: Config{BufferSize: maxBufferSize + 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Copy(context.Background(), test.source, test.destination, test.size, test.config)
			if err == nil || report.Status != StatusFailed || report.Failure == nil {
				t.Fatalf("unexpected validation result: report=%+v err=%v", report, err)
			}
		})
	}
}

func TestReportJSONIsStable(t *testing.T) {
	offset := uint64(0)
	report := Report{
		Schema:         ReportSchema,
		Status:         StatusFailed,
		PlannedBytes:   10,
		CompletedBytes: 0,
		Failure: &Failure{
			Kind:       "source_read",
			Message:    "read failed",
			ByteOffset: &offset,
		},
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"status":"failed","planned_bytes":10,"completed_bytes":0,"failure":{"kind":"source_read","message":"read failed","byte_offset":0}}`
	want = string(bytes.ReplaceAll([]byte(want), []byte{'\\'}, nil))
	if string(payload) != want {
		t.Fatalf("json = %s, want %s", payload, want)
	}
}

type recordingSyncWriter struct {
	buffer       bytes.Buffer
	maxWrite     int
	zeroWrite    bool
	invalidCount bool
	writeErr     error
	syncErr      error
	synced       bool
}

func (writer *recordingSyncWriter) Write(buffer []byte) (int, error) {
	if writer.invalidCount {
		return len(buffer) + 1, nil
	}
	if writer.zeroWrite {
		return 0, nil
	}
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	limit := len(buffer)
	if writer.maxWrite > 0 && writer.maxWrite < limit {
		limit = writer.maxWrite
	}
	return writer.buffer.Write(buffer[:limit])
}

func (writer *recordingSyncWriter) Sync() error {
	writer.synced = true
	return writer.syncErr
}
