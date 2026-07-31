//go:build linux

package windowstogo

import "testing"

func TestDecodeBlkidExport(t *testing.T) {
	for input, want := range map[string]string{
		`WINDOWS\ TO\ GO`: "WINDOWS TO GO",
		`plain`:           "plain",
		`A\x20B`:          "A B",
		`A\\B`:            `A\B`,
	} {
		got, err := decodeBlkidExport(input)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if got != want {
			t.Fatalf("decode %q=%q, want %q", input, got, want)
		}
	}
	for _, input := range []string{`bad\`, `bad\q`, `bad\x0`} {
		if _, err := decodeBlkidExport(input); err == nil {
			t.Fatalf("invalid escape %q accepted", input)
		}
	}
}
