//go:build linux

package nonbootable

import (
	"strings"
	"testing"
)

func TestMBRExecutionBoundary(t *testing.T) {
	// With 512-byte logical sectors, a partition ending at sector 2^32 is
	// representable because the final inclusive sector is 2^32-1.
	maximumRepresentableSize := mbrAddressSpaceSectors * 512
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("e", 64),
		DeviceSizeBytes:   maximumRepresentableSize,
		LogicalSectorSize: 512,
		Scheme:            "mbr",
		Filesystem:        "ext4",
		Label:             "DATA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPartitionTable(plan); err != nil {
		t.Fatalf("maximum representable MBR layout was rejected: %v", err)
	}

	tooLarge, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("f", 64),
		DeviceSizeBytes:   maximumRepresentableSize + 2*1024*1024,
		LogicalSectorSize: 512,
		Scheme:            "mbr",
		Filesystem:        "ext4",
		Label:             "DATA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPartitionTable(tooLarge); err == nil {
		t.Fatal("unrepresentable MBR layout was accepted")
	}
	if _, err := SfdiskScript(tooLarge); err == nil {
		t.Fatal("unrepresentable MBR layout produced a destructive script")
	}
}

func TestGPTHasNoMBRAddressLimit(t *testing.T) {
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("0", 64),
		DeviceSizeBytes:   4 * 1024 * 1024 * 1024 * 1024,
		LogicalSectorSize: 4096,
		Scheme:            "gpt",
		Filesystem:        "ext4",
		Label:             "ARCHIVE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPartitionTable(plan); err != nil {
		t.Fatalf("valid large GPT layout was rejected: %v", err)
	}
}
