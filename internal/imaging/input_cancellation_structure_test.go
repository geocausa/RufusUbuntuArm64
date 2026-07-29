package imaging

import (
	"os"
	"strings"
	"testing"
)

func readImagingSource(t *testing.T, name string) string {
	t.Helper()
	source, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func TestPreparedOutputUsesContextAwareFullWrites(t *testing.T) {
	text := readImagingSource(t, "input.go")
	if !strings.Contains(text, "writeFullContext(ctx, writer, buffer[:n])") {
		t.Fatal("compressed preparation output is not bound to cancellation between partial writes")
	}
	if strings.Contains(text, "writeFull(writer, buffer[:n])") {
		t.Fatal("compressed preparation still uses the context-free partial-write loop")
	}
}

func TestRawWriterHasNoContextFreeFullWriteFallback(t *testing.T) {
	text := readImagingSource(t, "imaging.go")
	if !strings.Contains(text, "writeFullContext(ctx, dst, buf[:n])") {
		t.Fatal("raw target writes are not bound to the operation context")
	}
	if strings.Contains(text, "func writeFull(") {
		t.Fatal("context-free full-write wrapper was reintroduced")
	}
}
