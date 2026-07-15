package imaging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndVerifyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "image.bin")
	dst := filepath.Join(dir, "device.bin")
	payload := make([]byte, 2*1024*1024+37)
	for i := range payload {
		payload[i] = byte((i * 31) % 251)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, make([]byte, len(payload)+4096), 0o600); err != nil {
		t.Fatal(err)
	}

	written, err := WriteImage(context.Background(), src, dst, WriteOptions{BufferSize: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	if written != uint64(len(payload)) {
		t.Fatalf("written=%d want=%d", written, len(payload))
	}
	if _, err := VerifyImage(context.Background(), src, dst, nil); err != nil {
		t.Fatal(err)
	}
}
