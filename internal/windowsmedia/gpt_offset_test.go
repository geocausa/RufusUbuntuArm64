//go:build linux

package windowsmedia

import (
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func TestWriteGPTRejectsTargetBeyondSignedOffsetRange(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "gpt-target-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = writeSinglePartitionGPT(file, uint64(math.MaxInt64)+1, 512, "RUFUS")
	if err == nil || !strings.Contains(err.Error(), "signed file-offset") {
		t.Fatalf("signed-offset error = %v", err)
	}
}

func TestWriteGPTMetadataRejectsShortWrite(t *testing.T) {
	target := &shortWriteFile{File: mustTemporaryFile(t)}
	defer target.Close()
	_, err := writeGPTMetadataAt(target, []byte{1, 2}, 0)
	if err == nil || !strings.Contains(err.Error(), io.ErrShortWrite.Error()) {
		t.Fatalf("short-write error = %v", err)
	}
}

type shortWriteFile struct{ *os.File }

func (file *shortWriteFile) WriteAt(data []byte, offset int64) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func mustTemporaryFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "short-write-")
	if err != nil {
		t.Fatal(err)
	}
	return file
}
