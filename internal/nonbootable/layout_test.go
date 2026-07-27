//go:build linux

package nonbootable

import (
	"strings"
	"testing"
)

func TestBuildPartitionTableUsesExactReviewedGeometry(t *testing.T) {
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("a", 64),
		DeviceSizeBytes:   16 * 1024 * 1024 * 1024,
		LogicalSectorSize: 512,
		Scheme:            "gpt",
		Filesystem:        "fat32",
		Label:             "data",
	})
	if err != nil {
		t.Fatal(err)
	}
	table, err := BuildPartitionTable(plan)
	if err != nil {
		t.Fatal(err)
	}
	if table.StartSector != 2048 {
		t.Fatalf("start sector=%d, want 2048", table.StartSector)
	}
	if table.SizeSectors != plan.PartitionSizeBytes/512 {
		t.Fatalf("size sectors=%d, want %d", table.SizeSectors, plan.PartitionSizeBytes/512)
	}
	if table.PartitionType != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" {
		t.Fatalf("unexpected GPT type %q", table.PartitionType)
	}
	if table.Label != "DATA" {
		t.Fatalf("FAT32 label was not canonicalized: %q", table.Label)
	}
}

func TestSfdiskScriptIsDeterministicAndExplicit(t *testing.T) {
	request := Request{
		DevicePath:        "/dev/mmcblk1",
		ExpectedIdentity:  strings.Repeat("b", 64),
		DeviceSizeBytes:   8 * 1024 * 1024 * 1024,
		LogicalSectorSize: 4096,
		Scheme:            "mbr",
		Filesystem:        "ext4",
		Label:             "ARCHIVE",
	}
	first, err := BuildPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	firstScript, err := SfdiskScript(first)
	if err != nil {
		t.Fatal(err)
	}
	secondScript, err := SfdiskScript(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstScript != secondScript {
		t.Fatal("identical plans produced different sfdisk scripts")
	}
	expected := "label: dos\nunit: sectors\n\nstart=256, size=2096640, type=83\n"
	if firstScript != expected {
		t.Fatalf("script mismatch\n got: %q\nwant: %q", firstScript, expected)
	}
	if strings.Contains(firstScript, "bootable") || strings.Contains(firstScript, "default") {
		t.Fatal("data-only script contains an implicit boot or default directive")
	}
}

func TestSfdiskScriptRejectsTamperedPlan(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.PartitionSizeBytes -= plan.LogicalSectorSize
	if _, err := SfdiskScript(plan); err == nil {
		t.Fatal("tampered plan was translated into a destructive script")
	}
}

func TestGPTScriptNamesDataPartitionWithoutBootClaims(t *testing.T) {
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdc",
		ExpectedIdentity:  strings.Repeat("c", 64),
		DeviceSizeBytes:   4 * 1024 * 1024 * 1024,
		LogicalSectorSize: 512,
		Scheme:            "gpt",
		Filesystem:        "exfat",
		Label:             "TRANSFER",
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := SfdiskScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"label: gpt\n",
		"unit: sectors\n",
		"type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		"name=RUFUSARM64-DATA",
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("script is missing %q: %q", fragment, script)
		}
	}
	if strings.Contains(strings.ToLower(script), "boot") {
		t.Fatalf("data-only script contains a bootability claim: %q", script)
	}
}
