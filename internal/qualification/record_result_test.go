//go:build linux

package qualification

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWriteRecordReturnsPublishedCanonicalRecord(t *testing.T) {
	root := t.TempDir()
	record := validRecord()
	record.Creator = "  " + record.Creator + "  "
	record.Architecture = strings.ToUpper(record.Architecture)
	record.Family = strings.ToUpper(record.Family)
	record.DisplayName = "  " + record.DisplayName + "  "
	record.BootParameter = "  " + record.BootParameter + "  "
	record.PatchedPaths = append(record.PatchedPaths, record.PatchedPaths[0])

	stored, err := WriteRecord(root, record)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVerifiedRecord(filepath.Join(root, filepath.FromSlash(stored.Path)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Record, loaded.Record) {
		t.Fatalf("write result differs from published canonical record:\nstored=%#v\nloaded=%#v", stored.Record, loaded.Record)
	}
	if stored.SHA256 != loaded.SHA256 {
		t.Fatalf("write result digest %q differs from verified digest %q", stored.SHA256, loaded.SHA256)
	}
}
