//go:build linux

package windowsmedia

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWindowsPayloadFixture(t *testing.T, root string, payloads ...string) {
	t.Helper()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	for _, name := range payloads {
		writeTestFile(t, filepath.Join(root, "sources", name), []byte(name))
	}
}

func TestCapabilityPayloadFacts(t *testing.T) {
	for _, test := range []struct {
		name  string
		plan  mediaPlan
		kind  string
		parts int
	}{
		{name: "WIM", plan: mediaPlan{InstallPath: "/iso/sources/install.wim"}, kind: "WIM", parts: 1},
		{name: "ESD", plan: mediaPlan{InstallPath: "/iso/SOURCES/INSTALL.ESD"}, kind: "ESD", parts: 1},
		{name: "split SWM", plan: mediaPlan{ExistingSplitFiles: []string{"install.swm", "install2.swm", "install3.swm"}}, kind: "SWM", parts: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, parts, err := capabilityPayloadFacts(test.plan)
			if err != nil {
				t.Fatal(err)
			}
			if kind != test.kind || parts != test.parts {
				t.Fatalf("kind=%q parts=%d, want %q %d", kind, parts, test.kind, test.parts)
			}
		})
	}
	if _, _, err := capabilityPayloadFacts(mediaPlan{}); err == nil {
		t.Fatal("missing payload facts were accepted")
	}
}

func TestInspectMountedISODisclosesWIMESDAndSplitSWM(t *testing.T) {
	for _, test := range []struct {
		name     string
		payloads []string
		kind     string
		parts    int
	}{
		{name: "WIM", payloads: []string{"install.wim"}, kind: "WIM", parts: 1},
		{name: "ESD", payloads: []string{"install.esd"}, kind: "ESD", parts: 1},
		{name: "SWM", payloads: []string{"install.swm", "install2.swm", "install3.swm"}, kind: "SWM", parts: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeWindowsPayloadFixture(t, root, test.payloads...)
			plan, err := inspectMountedISO(root)
			if err != nil {
				t.Fatal(err)
			}
			kind, parts, err := capabilityPayloadFacts(plan)
			if err != nil {
				t.Fatal(err)
			}
			if kind != test.kind || parts != test.parts {
				t.Fatalf("kind=%q parts=%d, want %q %d", kind, parts, test.kind, test.parts)
			}
			if test.kind == "SWM" && plan.InstallPath != "" {
				t.Fatalf("split media unexpectedly selected a standalone install path: %q", plan.InstallPath)
			}
		})
	}
}

func TestInspectMountedISORejectsConflictingPayloadFamilies(t *testing.T) {
	for _, payloads := range [][]string{
		{"install.wim", "install.esd"},
		{"install.wim", "install.swm"},
		{"install.esd", "install.swm", "install2.swm"},
	} {
		root := t.TempDir()
		writeWindowsPayloadFixture(t, root, payloads...)
		if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "conflicting installation payloads") {
			t.Fatalf("payloads %v were accepted: %v", payloads, err)
		}
	}
}

func TestInspectMountedISORejectsIncompleteOrDuplicateSplitSequences(t *testing.T) {
	missingFirst := t.TempDir()
	writeWindowsPayloadFixture(t, missingFirst, "install2.swm")
	if _, err := inspectMountedISO(missingFirst); err == nil || !strings.Contains(err.Error(), "missing sources/install.swm") {
		t.Fatalf("missing first part accepted: %v", err)
	}

	missingMiddle := t.TempDir()
	writeWindowsPayloadFixture(t, missingMiddle, "install.swm", "install3.swm")
	if _, err := inspectMountedISO(missingMiddle); err == nil || !strings.Contains(err.Error(), "missing part 2") {
		t.Fatalf("missing middle part accepted: %v", err)
	}

	duplicate := t.TempDir()
	writeWindowsPayloadFixture(t, duplicate, "install.swm", "install2.swm")
	if err := os.Rename(filepath.Join(duplicate, "sources", "install2.swm"), filepath.Join(duplicate, "sources", "INSTALL2.SWM")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(duplicate, "sources", "install2.swm"), []byte("duplicate"))
	if _, err := inspectMountedISO(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate split Windows image parts") {
		t.Fatalf("case-colliding duplicate accepted: %v", err)
	}
}

func TestCapabilityAnalysisJSONFieldsAreStable(t *testing.T) {
	analysis := CapabilityAnalysis{PayloadKind: "SWM", PayloadParts: 4}
	if analysis.PayloadKind != "SWM" || analysis.PayloadParts != 4 {
		t.Fatalf("analysis=%#v", analysis)
	}
}
