//go:build linux

package qualification

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeRecordRejectsPropertyKeyCollisions(t *testing.T) {
	for attempt := 0; attempt < 64; attempt++ {
		record := validRecord()
		record.Properties = map[string]string{
			"channel":   "stable",
			" channel ": "testing",
		}
		_, err := NormalizeRecord(record)
		if err == nil || !strings.Contains(err.Error(), "collide after normalization") {
			t.Fatalf("attempt %d collision error = %v", attempt, err)
		}
	}
}

func TestMarshalRecordKeepsNonCollidingPropertiesCanonical(t *testing.T) {
	record := validRecord()
	record.Properties = map[string]string{
		" channel ": " stable ",
		"architecture": " arm64 ",
	}
	first, firstDigest, err := MarshalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := MarshalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("canonical property serialization changed between calls")
	}
	normalized, err := NormalizeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"architecture": "arm64", "channel": "stable"}
	if !reflect.DeepEqual(normalized.Properties, want) {
		t.Fatalf("normalized properties = %#v; want %#v", normalized.Properties, want)
	}
}
