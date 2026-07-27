package imaging

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareZIPRejectsUnsupportedCompressionMethod(t *testing.T) {
	var archiveBytes bytes.Buffer
	archive := zip.NewWriter(&archiveBytes)
	entry, err := archive.Create("disk.img")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(testRawImage()); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	data := archiveBytes.Bytes()
	local := bytes.Index(data, []byte{'P', 'K', 3, 4})
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	if local < 0 || central < 0 {
		t.Fatal("generated ZIP is missing local or central file headers")
	}
	// Compression method is a 16-bit field at offset 8 in the local header and
	// offset 10 in the central directory header. Method 99 is deliberately not
	// registered by archive/zip.
	binary.LittleEndian.PutUint16(data[local+8:local+10], 99)
	binary.LittleEndian.PutUint16(data[central+10:central+12], 99)

	path := filepath.Join(t.TempDir(), "unsupported-method.zip")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity := inspectIdentity(t, path)
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if prepared != nil {
		prepared.Close()
		t.Fatal("unsupported ZIP compression unexpectedly produced a prepared image")
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsupported compression") {
		t.Fatalf("unsupported ZIP compression was not rejected clearly: %v", err)
	}
}
