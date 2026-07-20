//go:build linux

package nonbootable

import (
	"encoding/json"
	"strings"
	"testing"
)

const gib = uint64(1024 * 1024 * 1024)

func baseRequest() Request {
	return Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  "usb:vendor:model:serial:size",
		DeviceSizeBytes:   8 * gib,
		LogicalSectorSize: 512,
		Scheme:            "gpt",
		Filesystem:        "fat32",
		Label:             "rufus arm64",
	}
}

func TestBuildPlanCanonicalGPTFAT32(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != 1 || plan.Mode != "non-bootable" || plan.Bootable || !plan.Destructive {
		t.Fatalf("unexpected envelope: %#v", plan)
	}
	if plan.Scheme != SchemeGPT || plan.Filesystem != FilesystemFAT32 || plan.FilesystemDisplay != "FAT32" {
		t.Fatalf("unexpected format contract: %#v", plan)
	}
	if plan.Label != "RUFUS ARM64" {
		t.Fatalf("label = %q, want canonical FAT label", plan.Label)
	}
	if plan.PartitionStartBytes != 1024*1024 {
		t.Fatalf("start = %d", plan.PartitionStartBytes)
	}
	if plan.PartitionSizeBytes != 8*gib-2*1024*1024 {
		t.Fatalf("size = %d", plan.PartitionSizeBytes)
	}
	if plan.PartitionType != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" {
		t.Fatalf("partition type = %q", plan.PartitionType)
	}
	wantTools := []string{"sfdisk", "blockdev", "udevadm", "mkfs.vfat", "fsck.vfat"}
	if strings.Join(plan.RequiredTools, ",") != strings.Join(wantTools, ",") {
		t.Fatalf("tools = %#v", plan.RequiredTools)
	}
	phrase, err := ConfirmationPhrase(plan)
	if err != nil {
		t.Fatal(err)
	}
	if phrase != "FORMAT /dev/sdb AS FAT32 USING GPT LABEL RUFUS ARM64" {
		t.Fatalf("phrase = %q", phrase)
	}
}

func TestBuildPlanMBRExt4AndEmptyLabel(t *testing.T) {
	request := baseRequest()
	request.Scheme = "msdos"
	request.Filesystem = "ext4"
	request.Label = ""
	request.LogicalSectorSize = 4096
	plan, err := BuildPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Scheme != SchemeMBR || plan.PartitionType != "83" || plan.FilesystemDisplay != "ext4" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if plan.PartitionStartBytes%4096 != 0 || plan.PartitionSizeBytes%4096 != 0 {
		t.Fatalf("unaligned geometry: %#v", plan)
	}
	phrase, err := ConfirmationPhrase(plan)
	if err != nil {
		t.Fatal(err)
	}
	if phrase != "FORMAT /dev/sdb AS ext4 USING MBR WITHOUT A LABEL" {
		t.Fatalf("phrase = %q", phrase)
	}
}

func TestFilesystemAliasesAndContracts(t *testing.T) {
	for input, want := range map[string]string{
		"fat":   FilesystemFAT32,
		"VFAT":  FilesystemFAT32,
		"exfat": FilesystemExFAT,
		"NTFS":  FilesystemNTFS,
		"ext4":  FilesystemExt4,
	} {
		got, err := NormalizeFilesystem(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeFilesystem(%q) = %q, %v", input, got, err)
		}
	}
	for input, want := range map[string]string{"": SchemeGPT, "GPT": SchemeGPT, "msdos": SchemeMBR} {
		got, err := NormalizeScheme(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeScheme(%q) = %q, %v", input, got, err)
		}
	}

	for filesystem, display := range map[string]string{
		FilesystemFAT32: "FAT32",
		FilesystemExFAT: "exFAT",
		FilesystemNTFS:  "NTFS",
		FilesystemExt4:  "ext4",
	} {
		request := baseRequest()
		request.Filesystem = filesystem
		request.Label = "DATA"
		plan, err := BuildPlan(request)
		if err != nil {
			t.Fatalf("%s: %v", filesystem, err)
		}
		if plan.FilesystemDisplay != display || len(plan.RequiredTools) != 5 {
			t.Fatalf("%s plan = %#v", filesystem, plan)
		}
	}
}

func TestBuildPlanRejectsUnsafeOrUnsupportedInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{name: "relative device", mutate: func(value *Request) { value.DevicePath = "dev/sdb" }, want: "beneath /dev"},
		{name: "unclean device", mutate: func(value *Request) { value.DevicePath = "/dev/../tmp/disk" }, want: "beneath /dev"},
		{name: "missing identity", mutate: func(value *Request) { value.ExpectedIdentity = " " }, want: "identity"},
		{name: "unsupported sector", mutate: func(value *Request) { value.LogicalSectorSize = 1024 }, want: "512 or 4096"},
		{name: "small device", mutate: func(value *Request) { value.DeviceSizeBytes = 32 * 1024 * 1024 }, want: "too small"},
		{name: "scheme", mutate: func(value *Request) { value.Scheme = "apm" }, want: "GPT or MBR"},
		{name: "filesystem", mutate: func(value *Request) { value.Filesystem = "btrfs" }, want: "FAT32, exFAT, NTFS, or ext4"},
		{name: "fat punctuation", mutate: func(value *Request) { value.Label = "DATA!" }, want: "ASCII"},
		{name: "fat too long", mutate: func(value *Request) { value.Label = "TWELVE CHARS" }, want: "11 bytes"},
		{name: "leading space", mutate: func(value *Request) { value.Label = " DATA" }, want: "leading or trailing"},
		{name: "control", mutate: func(value *Request) { value.Filesystem = "ntfs"; value.Label = "BAD\nLABEL" }, want: "control"},
		{name: "ext4 bytes", mutate: func(value *Request) { value.Filesystem = "ext4"; value.Label = "ééééééééé" }, want: "16 bytes"},
		{name: "exfat characters", mutate: func(value *Request) { value.Filesystem = "exfat"; value.Label = "1234567890123456" }, want: "15 characters"},
		{name: "ntfs characters", mutate: func(value *Request) { value.Filesystem = "ntfs"; value.Label = strings.Repeat("x", 33) }, want: "32 characters"},
		{name: "fat capacity", mutate: func(value *Request) { value.DeviceSizeBytes = maximumFAT32Size + 4*1024*1024 }, want: "compatibility contract"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := baseRequest()
			test.mutate(&request)
			_, err := BuildPlan(request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPlanJSONIsStableAndExplicitlyNonBootable(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("JSON is not deterministic:\n%s\n%s", first, second)
	}
	text := string(first)
	for _, marker := range []string{`"schema":1`, `"mode":"non-bootable"`, `"bootable":false`, `"destructive":true`} {
		if !strings.Contains(text, marker) {
			t.Fatalf("JSON is missing %s: %s", marker, text)
		}
	}
}

func TestConfirmationRejectsTamperedPlan(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.PartitionType = "83"
	if _, err := ConfirmationPhrase(plan); err == nil {
		t.Fatal("tampered partition type was accepted")
	}
}
