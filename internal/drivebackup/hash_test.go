package drivebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestHashExactHashesBoundedBytesWithPhaseProgress(t *testing.T) {
	data := bytes.Repeat([]byte("descriptor-hash"), 1024)
	var progress []Progress
	got, err := HashExact(context.Background(), bytes.NewReader(append(data, []byte("ignored trailing bytes")...)), uint64(len(data)), "hash_source", func(event Progress) {
		progress = append(progress, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash=%q want=%x", got, want)
	}
	if len(progress) < 2 || progress[0] != (Progress{Phase: "hash_source", Done: 0, Total: uint64(len(data))}) {
		t.Fatalf("progress=%+v", progress)
	}
	var previous uint64
	for index, event := range progress {
		if event.Phase != "hash_source" || event.Total != uint64(len(data)) || event.Done < previous || event.Done > event.Total {
			t.Fatalf("event %d invalid: previous=%d event=%+v", index, previous, event)
		}
		previous = event.Done
	}
	if previous != uint64(len(data)) {
		t.Fatalf("final progress=%d", previous)
	}
}

func TestHashExactFailsClosed(t *testing.T) {
	if _, err := HashExact(context.Background(), bytes.NewReader([]byte("short")), 32, "hash", nil); err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashExact(cancelled, bytes.NewReader([]byte("data")), 4, "hash", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	if _, err := HashExact(context.Background(), nil, 1, "hash", nil); err == nil {
		t.Fatal("nil source succeeded")
	}
	if _, err := HashExact(context.Background(), bytes.NewReader(nil), 0, "hash", nil); err == nil {
		t.Fatal("zero size succeeded")
	}
}
