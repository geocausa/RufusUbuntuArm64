package device

import "testing"

func TestIdentityTokenIgnoresChildPartitionLayout(t *testing.T) {
	base := BlockDevice{
		Path:         "/dev/sda",
		Type:         "disk",
		Size:         64 * 1024 * 1024 * 1024,
		MajorMinor:   "8:0",
		Serial:       "SERIAL-1",
		WWN:          "WWN-1",
		DiskSequence: "42",
		Vendor:       "Vendor",
		Model:        "Model",
		Transport:    "usb",
		Removable:    false,
		ReadOnly:     false,
		Children: []BlockDevice{{
			Path:        "/dev/sda1",
			Type:        "part",
			Size:        1024 * 1024 * 1024,
			MajorMinor:  "8:1",
			Mountpoints: []string{"/media/old"},
		}},
	}
	before := IdentityToken(base)
	base.Children = []BlockDevice{
		{Path: "/dev/sda1", Type: "part", Size: 4 * 1024 * 1024 * 1024, MajorMinor: "8:1"},
		{Path: "/dev/sda2", Type: "part", Size: 60 * 1024 * 1024 * 1024, MajorMinor: "8:2"},
	}
	if after := IdentityToken(base); after != before {
		t.Fatalf("whole-disk identity changed after only the child partition layout changed: before=%s after=%s", before, after)
	}
}

func TestIdentityTokenChangesForReconnectedOrDifferentDisk(t *testing.T) {
	base := BlockDevice{
		Path:         "/dev/sda",
		Type:         "disk",
		Size:         64 * 1024 * 1024 * 1024,
		MajorMinor:   "8:0",
		Serial:       "SERIAL-1",
		WWN:          "WWN-1",
		DiskSequence: "42",
		Vendor:       "Vendor",
		Model:        "Model",
		Transport:    "usb",
	}
	original := IdentityToken(base)
	mutations := []struct {
		name   string
		mutate func(*BlockDevice)
	}{
		{"disk sequence", func(value *BlockDevice) { value.DiskSequence = "43" }},
		{"major minor", func(value *BlockDevice) { value.MajorMinor = "8:16" }},
		{"serial", func(value *BlockDevice) { value.Serial = "SERIAL-2" }},
		{"wwn", func(value *BlockDevice) { value.WWN = "WWN-2" }},
		{"size", func(value *BlockDevice) { value.Size++ }},
		{"path", func(value *BlockDevice) { value.Path = "/dev/sdb" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if got := IdentityToken(changed); got == original {
				t.Fatalf("identity did not change after %s changed", test.name)
			}
		})
	}
}
