package device

import "testing"

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
