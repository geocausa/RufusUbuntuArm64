//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZeroPartition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partition")
	original := make([]byte, 3*1024*1024+17)
	for i := range original {
		original[i] = 0xa5
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var last Event
	if err := zeroPartition(context.Background(), path, uint64(len(original)), func(ev Event) { last = ev }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d was not zeroed", i)
		}
	}
	if last.Done != uint64(len(original)) || last.Total != uint64(len(original)) {
		t.Fatalf("event=%#v", last)
	}
}

func TestZeroPartitionCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partition")
	if err := os.WriteFile(path, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := zeroPartition(ctx, path, 1024, nil); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestVerifyZeroPartition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partition")
	data := make([]byte, 2*1024*1024+9)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyZeroPartition(context.Background(), path, uint64(len(data)), nil); err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] = 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyZeroPartition(context.Background(), path, uint64(len(data)), nil); err == nil {
		t.Fatal("corruption was not detected")
	}
}
