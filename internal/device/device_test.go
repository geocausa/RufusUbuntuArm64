package device

import (
	"os"
	"testing"
)

func TestParseBool(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{true, true}, {false, false}, {float64(1), true}, {float64(0), false}, {"1", true}, {"0", false}, {nil, false},
	}
	for _, tc := range cases {
		got, err := parseBool(tc.in)
		if err != nil {
			t.Fatalf("parseBool(%v): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseBool(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestMountedDescendants(t *testing.T) {
	dev := BlockDevice{
		Path: "/dev/sda",
		Type: "disk",
		Children: []BlockDevice{
			{Path: "/dev/sda1", Type: "part", Mountpoints: []string{"/media/test"}},
			{Path: "/dev/sda2", Type: "part"},
		},
	}
	got := MountedDescendants(dev)
	if len(got) != 1 || got[0].Path != "/dev/sda1" {
		t.Fatalf("MountedDescendants() = %#v", got)
	}
}

func TestIdentityTokenChangesWithKernelIdentity(t *testing.T) {
	base := BlockDevice{Path: "/dev/sda", Type: "disk", Size: 1024, MajorMinor: "8:0", Serial: "ABC", Transport: "usb"}
	first := IdentityToken(base)
	base.Identity = first
	if got := IdentityToken(base); got != first {
		t.Fatalf("identity included derived Identity field: got %s want %s", got, first)
	}
	base.MajorMinor = "8:16"
	if got := IdentityToken(base); got == first {
		t.Fatal("identity did not change when MAJ:MIN changed")
	}
}

func TestNormalRemovableTargetPolicy(t *testing.T) {
	cases := []struct {
		name string
		dev  BlockDevice
		want bool
	}{
		{"removable", BlockDevice{Removable: true}, true},
		{"usb enclosure rm zero", BlockDevice{Transport: "usb"}, true},
		{"internal mmc", BlockDevice{Transport: "mmc"}, false},
		{"removable mmc", BlockDevice{Transport: "mmc", Removable: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNormalRemovableTarget(tc.dev); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestListParsesIdentityFields(t *testing.T) {
	fakeBin := t.TempDir()
	script := `#!/bin/sh
cat <<'JSON'
{"blockdevices":[{"name":"sda","path":"/dev/sda","type":"disk","size":16000000000,"model":"Flash","vendor":"Acme","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"SER123","wwn":"WWN123"}]}
JSON
`
	path := fakeBin + "/lsblk"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	devices, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("len=%d", len(devices))
	}
	dev := devices[0]
	if dev.MajorMinor != "8:0" || dev.Serial != "SER123" || dev.WWN != "WWN123" || dev.Identity == "" {
		t.Fatalf("identity fields missing: %#v", dev)
	}
	if !dev.Hotplug || !IsNormalRemovableTarget(dev) {
		t.Fatalf("USB hotplug target was not accepted: %#v", dev)
	}
}

func TestListIncludesKernelDiskSequenceInIdentity(t *testing.T) {
	fakeBin := t.TempDir()
	script := `#!/bin/sh
cat <<'JSON'
{"blockdevices":[{"name":"testusb","path":"/dev/testusb","type":"disk","size":16000000000,"model":"Flash","vendor":"Acme","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"","wwn":""}]}
JSON
`
	if err := os.WriteFile(fakeBin+"/lsblk", []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sysRoot := t.TempDir()
	if err := os.MkdirAll(sysRoot+"/testusb", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sysRoot+"/testusb/diskseq", []byte("1042\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldRoot := sysClassBlockRoot
	sysClassBlockRoot = sysRoot
	t.Cleanup(func() { sysClassBlockRoot = oldRoot })
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	devices, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].DiskSequence != "1042" {
		t.Fatalf("disk sequence missing: %#v", devices)
	}
	original := devices[0].Identity
	devices[0].DiskSequence = "1043"
	if IdentityToken(devices[0]) == original {
		t.Fatal("identity did not change with kernel disk sequence")
	}
}
