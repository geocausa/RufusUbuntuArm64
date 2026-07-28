package imaging

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteImageInterruptionQualification(t *testing.T) {
	makeFixture := func(t *testing.T) (*os.File, string, []byte) {
		t.Helper()
		directory := t.TempDir()
		sourcePath := filepath.Join(directory, "source.img")
		targetPath := filepath.Join(directory, "target.img")
		source := bytes.Repeat([]byte("RUFUS-INTERRUPTION-"), 1024)
		target := bytes.Repeat([]byte{0x5a}, len(source))
		if err := os.WriteFile(sourcePath, source, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetPath, target, 0o600); err != nil {
			t.Fatal(err)
		}
		sourceFile, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sourceFile.Close() })
		return sourceFile, targetPath, target
	}

	t.Run("cancellation after first chunk", func(t *testing.T) {
		source, targetPath, original := makeFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		result, err := WriteOpenImageWithResult(ctx, source, targetPath, WriteOptions{
			BufferSize: 1024,
			TargetSize: uint64(len(original)),
			afterWriteChunk: func(uint64) {
				calls++
				if calls == 1 {
					cancel()
				}
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want context cancellation", err)
		}
		if result.BytesWritten == 0 || result.BytesWritten >= uint64(len(original)) || result.SHA256 != "" {
			t.Fatalf("unsafe cancellation result: %+v", result)
		}
		target, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Equal(target, original) {
			t.Fatal("post-write cancellation left no inspectable target mutation")
		}
	})

	t.Run("final synchronization failure", func(t *testing.T) {
		source, targetPath, original := makeFixture(t)
		syncFailure := errors.New("injected final sync failure")
		result, err := WriteOpenImageWithResult(context.Background(), source, targetPath, WriteOptions{
			BufferSize: 1024,
			TargetSize: uint64(len(original)),
			syncTarget: func(*os.File) error { return syncFailure },
		})
		if !errors.Is(err, syncFailure) || !strings.Contains(err.Error(), "sync target") {
			t.Fatalf("error=%v, want injected target sync failure", err)
		}
		if result.BytesWritten != uint64(len(original)) || result.SHA256 != "" {
			t.Fatalf("sync failure fabricated successful evidence: %+v", result)
		}
		target, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Equal(target, original) {
			t.Fatal("sync failure test did not reach target mutation")
		}
	})
}
