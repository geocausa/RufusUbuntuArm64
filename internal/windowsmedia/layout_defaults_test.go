//go:build linux

package windowsmedia

import "testing"

func TestResolveWindowsLayoutDefaultsFromImage(t *testing.T) {
	dualBootX64 := mediaPlan{HasX64: true, HasBIOS: true, BIOSArchitecture: "amd64", HasBootmgr: true}
	for _, tc := range []struct {
		scheme     string
		target     string
		wantScheme string
		wantTarget string
	}{
		{"auto", "auto", "gpt", "uefi"},
		{"", "", "gpt", "uefi"},
		{"mbr", "auto", "mbr", "uefi"},
		{"auto", "bios", "mbr", "bios"},
		{"gpt", "uefi", "gpt", "uefi"},
	} {
		scheme, target, err := resolveWindowsLayout(dualBootX64, tc.scheme, tc.target)
		if err != nil || scheme != tc.wantScheme || target != tc.wantTarget {
			t.Fatalf("%+v => %s/%s, %v; want %s/%s", tc, scheme, target, err, tc.wantScheme, tc.wantTarget)
		}
	}
}

func TestResolveWindowsLayoutRejectsUnsafeCombinations(t *testing.T) {
	dualBootX64 := mediaPlan{HasX64: true, HasBIOS: true, BIOSArchitecture: "amd64", HasBootmgr: true}
	if _, _, err := resolveWindowsLayout(dualBootX64, "gpt", "bios"); err == nil {
		t.Fatal("GPT/BIOS was accepted")
	}
	if _, _, err := resolveWindowsLayout(mediaPlan{HasBootmgr: true}, "auto", "auto"); err == nil {
		t.Fatal("BIOS-only automatic layout was accepted before architecture binding")
	}
}
