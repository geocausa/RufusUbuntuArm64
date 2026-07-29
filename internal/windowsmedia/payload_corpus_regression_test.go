//go:build linux

package windowsmedia

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectMountedISOPayloadCaseCorpus(t *testing.T) {
	for _, test := range []struct {
		name     string
		payloads []string
		kind     string
		parts    int
	}{
		{name: "uppercase WIM", payloads: []string{"INSTALL.WIM"}, kind: "WIM", parts: 1},
		{name: "mixed-case ESD", payloads: []string{"Install.EsD"}, kind: "ESD", parts: 1},
		{name: "mixed-case SWM", payloads: []string{"INSTALL.SWM", "Install2.SwM"}, kind: "SWM", parts: 2},
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
				t.Fatalf("payload facts=%q/%d, want %q/%d", kind, parts, test.kind, test.parts)
			}
		})
	}
}

func TestInspectMountedISORejectsCaseCollidingCriticalPayloads(t *testing.T) {
	for _, names := range [][]string{
		{"install.wim", "INSTALL.WIM"},
		{"install.esd", "INSTALL.ESD"},
	} {
		root := t.TempDir()
		writeWindowsPayloadFixture(t, root, names...)
		if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "ambiguous case-insensitive") {
			t.Fatalf("case-colliding payloads %v were accepted: %v", names, err)
		}
	}

	root := t.TempDir()
	writeWindowsPayloadFixture(t, root, "install.wim")
	writeTestFile(t, filepath.Join(root, "sources", "BOOT.WIM"), []byte("collision"))
	if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "ambiguous case-insensitive") {
		t.Fatalf("case-colliding boot.wim was accepted: %v", err)
	}
}

func TestInspectMountedISORejectsSymlinkedCriticalPayload(t *testing.T) {
	root := t.TempDir()
	writeWindowsPayloadFixture(t, root)
	external := filepath.Join(t.TempDir(), "install.wim")
	if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "sources", "install.wim")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked install.wim was accepted: %v", err)
	}
}

func TestInspectMountedISORejectsUnboundedSplitIndex(t *testing.T) {
	root := t.TempDir()
	writeWindowsPayloadFixture(t, root, "install.swm", "install1025.swm")
	if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "supported limit") {
		t.Fatalf("out-of-scope split part was accepted: %v", err)
	}
}

func TestCapabilityPayloadFactsRejectsImpossiblePlans(t *testing.T) {
	if _, _, err := capabilityPayloadFacts(mediaPlan{
		InstallPath:        "/iso/sources/install.wim",
		ExistingSplitFiles: []string{"/iso/sources/install.swm"},
	}); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("standalone-plus-split plan was accepted: %v", err)
	}

	parts := make([]string, maxWindowsSplitParts+1)
	for index := range parts {
		parts[index] = filepath.Join("/iso/sources", "part")
	}
	if _, _, err := capabilityPayloadFacts(mediaPlan{ExistingSplitFiles: parts}); err == nil || !strings.Contains(err.Error(), "supported limit") {
		t.Fatalf("unbounded split plan was accepted: %v", err)
	}
}
