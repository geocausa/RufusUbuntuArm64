package freedos

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDevicePlan(t *testing.T) {
	plan, err := BuildDevicePlan(DeviceRequest{
		DevicePath:        "/dev/sdz",
		ExpectedIdentity:  "usb:vendor:model:serial",
		DeviceSizeBytes:   testMediaSize,
		LogicalSectorSize: 512,
		Label:             "FREEDOS",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != DevicePlanSchema || plan.Mode != DeviceMode || !plan.Bootable || !plan.Destructive {
		t.Fatalf("unexpected device-plan envelope: %+v", plan)
	}
	if plan.TargetCPU != "x86" || plan.Firmware != "BIOS or UEFI Legacy/CSM" || plan.Distribution != "FreeDOS 1.4" {
		t.Fatalf("unexpected platform boundary: %+v", plan)
	}
	if plan.PartitionStartBytes != 1024*1024 || plan.PartitionSizeBytes != 67584*512 ||
		plan.PartitionType != "0c" || plan.Filesystem != "FAT32" || plan.Label != "FREEDOS" {
		t.Fatalf("unexpected media binding: %+v", plan)
	}
	phrase, err := DeviceConfirmationPhrase(plan)
	if err != nil {
		t.Fatal(err)
	}
	if phrase != "WRITE FREEDOS 1.4 TO /dev/sdz FOR X86 BIOS LEGACY" {
		t.Fatalf("unexpected confirmation phrase %q", phrase)
	}
	first, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("identical FreeDOS plans produced different JSON")
	}
}

func TestBuildDevicePlanRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name    string
		request DeviceRequest
		want    string
	}{
		{
			name: "relative path",
			request: DeviceRequest{DevicePath: "dev/sdz", ExpectedIdentity: "identity", DeviceSizeBytes: testMediaSize,
				LogicalSectorSize: 512, Label: "FREEDOS"},
			want: "beneath /dev",
		},
		{
			name: "uncanonical identity",
			request: DeviceRequest{DevicePath: "/dev/sdz", ExpectedIdentity: " identity ", DeviceSizeBytes: testMediaSize,
				LogicalSectorSize: 512, Label: "FREEDOS"},
			want: "identity",
		},
		{
			name: "4k sector",
			request: DeviceRequest{DevicePath: "/dev/sdz", ExpectedIdentity: "identity", DeviceSizeBytes: testMediaSize,
				LogicalSectorSize: 4096, Label: "FREEDOS"},
			want: "512-byte",
		},
		{
			name: "invalid label",
			request: DeviceRequest{DevicePath: "/dev/sdz", ExpectedIdentity: "identity", DeviceSizeBytes: testMediaSize,
				LogicalSectorSize: 512, Label: "FreeDOS"},
			want: "uppercase ASCII",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildDevicePlan(test.request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestDevicePlanRejectsTampering(t *testing.T) {
	canonical, err := BuildDevicePlan(DeviceRequest{
		DevicePath:        "/dev/sdz",
		ExpectedIdentity:  "usb:vendor:model:serial",
		DeviceSizeBytes:   testMediaSize,
		LogicalSectorSize: 512,
		Label:             "FREEDOS",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*DevicePlan)
		want string
	}{
		{"envelope", func(plan *DevicePlan) { plan.Bootable = false }, "envelope"},
		{"path", func(plan *DevicePlan) { plan.DevicePath = "/dev/../tmp/disk" }, "device path"},
		{"identity", func(plan *DevicePlan) { plan.ExpectedIdentity = "" }, "identity"},
		{"target CPU", func(plan *DevicePlan) { plan.TargetCPU = "arm64" }, "platform"},
		{"firmware", func(plan *DevicePlan) { plan.Firmware = "UEFI" }, "platform"},
		{"device size", func(plan *DevicePlan) { plan.DeviceSizeBytes += 512 }, "binding"},
		{"media", func(plan *DevicePlan) { plan.Media.PartitionStartSector++ }, "media"},
		{"partition", func(plan *DevicePlan) { plan.PartitionStartBytes += 512 }, "partition"},
		{"filesystem", func(plan *DevicePlan) { plan.Filesystem = "exFAT" }, "partition"},
		{"label", func(plan *DevicePlan) { plan.Label = "OTHER" }, "media"},
		{"warnings", func(plan *DevicePlan) { plan.Warnings = plan.Warnings[:len(plan.Warnings)-1] }, "warnings"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			altered := canonical
			altered.Warnings = append([]string(nil), canonical.Warnings...)
			test.edit(&altered)
			if err := ValidateDevicePlan(altered); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
			if _, err := DeviceConfirmationPhrase(altered); err == nil {
				t.Fatal("confirmation accepted an altered FreeDOS plan")
			}
		})
	}
}
