package volumelabel

import (
	"strings"
	"testing"
)

func TestFAT32CanonicalPortableContract(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    string
		fallback string
		want     string
	}{
		{name: "uppercase", value: "win 11", want: "WIN 11"},
		{name: "fallback", fallback: "RUFUS-LIVE", want: "RUFUS-LIVE"},
		{name: "portable punctuation", value: "RUFUS_2026", want: "RUFUS_2026"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := FAT32(test.value, test.fallback)
			if err != nil || got != test.want {
				t.Fatalf("FAT32(%q, %q) = %q, %v; want %q", test.value, test.fallback, got, err, test.want)
			}
		})
	}
}

func TestFAT32RejectsNonPortableInput(t *testing.T) {
	for _, value := range []string{
		" leading",
		"trailing ",
		"TWELVE-CHARS",
		"BAD/NAME",
		"RUFUS-日本",
		"BAD\nNAME",
	} {
		if _, err := FAT32(value, ""); err == nil {
			t.Fatalf("accepted invalid FAT32 label %q", value)
		}
	}
	if _, err := FAT32(string([]byte{0xff}), ""); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestNTFSPreservesUnicodeCaseAndPunctuation(t *testing.T) {
	for _, value := range []string{
		"Rufus_日本",
		"MiXeD Case",
		"Δίσκος-2026",
		`Rufus:*?/\\|<>"`,
		strings.Repeat("😀", 16),
	} {
		got, err := NTFS(value, "")
		if err != nil || got != value {
			t.Fatalf("NTFS(%q) = %q, %v", value, got, err)
		}
	}
	got, err := NTFS("", "RufusArm64")
	if err != nil || got != "RufusArm64" {
		t.Fatalf("NTFS fallback = %q, %v", got, err)
	}
}

func TestNTFSRejectsAmbiguousOrInvalidLabels(t *testing.T) {
	for _, value := range []string{
		" leading",
		"trailing ",
		"BAD\nNAME",
		strings.Repeat("😀", 17),
		strings.Repeat("x", 33),
	} {
		if _, err := NTFS(value, ""); err == nil {
			t.Fatalf("accepted invalid NTFS label %q", value)
		}
	}
	if _, err := NTFS(string([]byte{0xff}), ""); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}
