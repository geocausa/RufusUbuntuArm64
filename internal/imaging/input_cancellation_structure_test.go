package imaging

import (
	"os"
	"strings"
	"testing"
)

func TestPreparedOutputUsesContextAwareFullWrites(t *testing.T) {
	source, err := os.ReadFile("input.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "writeFullContext(ctx, writer, buffer[:n])") {
		t.Fatal("compressed preparation output is not bound to cancellation between partial writes")
	}
	if strings.Contains(text, "writeFull(writer, buffer[:n])") {
		t.Fatal("compressed preparation still uses the context-free partial-write loop")
	}
}
