//go:build linux

package qualification

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRecordRequiresExactCanonicalBytes(t *testing.T) {
	canonical, _, err := MarshalRecord(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseRecord(canonical); err != nil {
		t.Fatalf("canonical record was rejected: %v", err)
	}

	withoutFinalNewline := bytes.TrimSuffix(append([]byte(nil), canonical...), []byte{'\n'})
	for name, data := range map[string][]byte{
		"leading whitespace":    append([]byte(" \n"), canonical...),
		"trailing blank line":   append(append([]byte(nil), canonical...), '\n'),
		"missing final newline": withoutFinalNewline,
		"space before newline":  append(append([]byte(nil), canonical[:len(canonical)-1]...), ' ', '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseRecord(data)
			if err == nil || !strings.Contains(err.Error(), "canonical form") {
				t.Fatalf("ParseRecord error = %v", err)
			}
		})
	}
}

func TestLoadVerifiedRecordRejectsWhitespaceOnlyByteChange(t *testing.T) {
	root := t.TempDir()
	stored, err := WriteRecord(root, validRecord())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(stored.Path))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(" \n"), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedRecord(path); err == nil || !strings.Contains(err.Error(), "canonical form") {
		t.Fatalf("LoadVerifiedRecord error = %v", err)
	}
}
