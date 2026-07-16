package main

import (
	"testing"

	"github.com/geocausa/RufusArm64/internal/imaging"
)

func TestSelectWriteMode(t *testing.T) {
	cases := []struct {
		name       string
		requested  string
		inspection imaging.ImageInfo
		force      bool
		want       string
		wantErr    bool
	}{
		{"hybrid iso raw", "auto", imaging.ImageInfo{HasISO9660: true, HasMBR: true, HasMBRPartition: true}, false, "raw", false},
		{"plain optical windows", "auto", imaging.ImageInfo{HasISO9660: true}, false, "windows", false},
		{"gpt raw", "auto", imaging.ImageInfo{HasGPT: true}, false, "raw", false},
		{"unknown rejected", "auto", imaging.ImageInfo{}, false, "", true},
		{"unknown expert force", "auto", imaging.ImageInfo{}, true, "raw", false},
		{"plain optical explicit raw rejected", "raw", imaging.ImageInfo{HasUDF: true}, false, "", true},
		{"plain optical expert force", "auto", imaging.ImageInfo{HasUDF: true}, true, "raw", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectWriteMode(tc.requested, tc.inspection, tc.force)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	if got := humanBytes(1024); got != "1.0 KiB" {
		t.Fatalf("got %q", got)
	}
}

func TestPKExecWriterRejectsExpertBypassFlags(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	for _, flag := range []string{"--allow-fixed", "--no-unmount", "--force-raw", "--allow-foreign-windows-architecture"} {
		args := []string{
			"write", "--image", "/tmp/image.iso", "--device", "/dev/sda",
			"--mode", "auto", "--yes", "--json-progress",
			"--expected-identity", "identity", "--cancel-file", "/run/user/1000/rufusarm64-test.cancel",
			flag,
		}
		err := run(args)
		if err == nil || err.Error() != "unsafe or unsupported arguments were supplied to the graphical privileged writer" {
			t.Fatalf("flag %s was not rejected at the privilege boundary: %v", flag, err)
		}
	}
}

func TestParseClusterSize(t *testing.T) {
	for input, want := range map[string]uint64{"": 0, "auto": 0, "4096": 4096, "32768": 32768} {
		got, err := parseClusterSize(input)
		if err != nil || got != want {
			t.Fatalf("%q => %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"2048", "65536", "8K"} {
		if _, err := parseClusterSize(input); err == nil {
			t.Fatalf("invalid cluster size %q accepted", input)
		}
	}
}
