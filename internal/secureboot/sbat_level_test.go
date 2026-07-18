package secureboot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSBATLevelAndShimComparisonSemantics(t *testing.T) {
	level, err := ParseSBATLevel([]byte("sbat,1,2025051000\nshim,4\ngrub,5\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if level.FormatGeneration != 1 || level.Datestamp != "2025051000" || len(level.Entries) != 3 {
		t.Fatalf("unexpected SBAT level: %#v", level)
	}
	revoked := level.Revocations([]SBATComponent{
		{Component: "sbat", Generation: 1},
		{Component: "shim", Generation: 3},
		{Component: "grub", Generation: 5},
		{Component: "grub.vendor", Generation: 1},
	})
	if len(revoked) != 1 || revoked[0].Component != "shim" || revoked[0].ImageGeneration != 3 || revoked[0].MinimumGeneration != 4 {
		t.Fatalf("unexpected revocations: %#v", revoked)
	}
}

func TestParseSBATLevelRejectsMalformedInputs(t *testing.T) {
	cases := map[string]string{
		"missing metadata":      "shim,4\n",
		"bad datestamp":         "sbat,1,2025\nshim,4\n",
		"zero generation":       "sbat,1,2025051000\nshim,0\n",
		"duplicate component":   "sbat,1,2025051000\nshim,4\nSHIM,5\n",
		"extra component field": "sbat,1,2025051000\nshim,4,unexpected\n",
		"whitespace padded":     "sbat,1,2025051000\nshim, 4\n",
		"non ascii":             "sbat,1,2025051000\nshim,4\u00a0\n",
		"blank row":             "sbat,1,2025051000\n\nshim,4\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSBATLevel([]byte(input), "test"); err == nil {
				t.Fatalf("malformed SBAT level accepted: %q", input)
			}
		})
	}
}

func TestLoadSBATLevelFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SbatLevel.csv")
	if err := os.WriteFile(path, []byte("sbat,1,2025051000\nshim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	level, err := LoadSBATLevelFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(level.Source, "SbatLevel.csv") || level.Datestamp != "2025051000" {
		t.Fatalf("unexpected loaded level: %#v", level)
	}
}
