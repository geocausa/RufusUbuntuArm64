package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/drivebackup"
)

func TestRunValidatesArgumentsBeforeDeviceAccess(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing device", args: nil, want: "--device is required"},
		{name: "missing output", args: []string{"--device", "/dev/does-not-exist"}, want: "--output is required"},
		{name: "positional", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "extra"}, want: "positional arguments"},
		{name: "yes without identity", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--yes"}, want: "--yes requires --expected-identity"},
		{name: "fixed without identity", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--allow-fixed"}, want: "--allow-fixed requires --expected-identity"},
		{name: "json run without yes", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--json", "--expected-identity", "token"}, want: "non-dry-run --json requires --yes"},
		{name: "progress without json", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--progress-json"}, want: "--progress-json requires non-dry-run --json"},
		{name: "progress on dry run", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--dry-run", "--json", "--progress-json"}, want: "--progress-json requires non-dry-run --json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestGraphicalInvocationRequiresGuardedIdentityBoundMode(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "dry run", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--expected-identity", "token", "--yes", "--json", "--dry-run"}, want: "graphical backup requires"},
		{name: "interactive", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--expected-identity", "token", "--json"}, want: "non-dry-run --json requires --yes"},
		{name: "fixed", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--expected-identity", "token", "--yes", "--json", "--allow-fixed"}, want: "normal removable sources"},
		{name: "no unmount", args: []string{"--device", "/dev/does-not-exist", "--output", "/tmp/out.img", "--expected-identity", "token", "--yes", "--json", "--no-unmount"}, want: "guarded unmounting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateSourceMetadata(t *testing.T) {
	base := device.BlockDevice{
		Path:      "/dev/sdz",
		Type:      "disk",
		Size:      8 * 1024 * 1024,
		Transport: "usb",
	}
	for _, test := range []struct {
		name       string
		selected   device.BlockDevice
		allowFixed bool
		want       string
	}{
		{name: "valid usb", selected: base},
		{name: "valid read only", selected: func() device.BlockDevice { value := base; value.ReadOnly = true; return value }()},
		{name: "path mismatch", selected: func() device.BlockDevice { value := base; value.Path = "/dev/sdy"; return value }(), want: "path mismatch"},
		{name: "partition", selected: func() device.BlockDevice { value := base; value.Type = "part"; return value }(), want: "whole disk"},
		{name: "zero size", selected: func() device.BlockDevice { value := base; value.Size = 0; return value }(), want: "unsupported size"},
		{name: "oversize", selected: func() device.BlockDevice { value := base; value.Size = math.MaxInt64 + 1; return value }(), want: "unsupported size"},
		{name: "fixed refused", selected: func() device.BlockDevice { value := base; value.Transport = ""; return value }(), want: "--allow-fixed"},
		{name: "fixed allowed", selected: func() device.BlockDevice { value := base; value.Transport = ""; return value }(), allowFixed: true},
		{name: "protected mount", selected: func() device.BlockDevice {
			value := base
			value.Children = []device.BlockDevice{{Path: "/dev/sdz1", Type: "part", Mountpoints: []string{"/home"}}}
			return value
		}(), want: "used by the running system"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSourceMetadata(base.Path, test.selected, test.allowFixed)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	for value, want := range map[uint64]string{
		0:           "0 B",
		1024:        "1.0 KiB",
		1024 * 1024: "1.0 MiB",
	} {
		if got := humanBytes(value); got != want {
			t.Fatalf("humanBytes(%d) = %q, want %q", value, got, want)
		}
	}
}

func TestMakeProgressEvent(t *testing.T) {
	event := makeProgressEvent(drivebackup.Progress{Done: 512, Total: 1024}, 2*time.Second)
	if event.Schema != 1 || event.Type != "progress" {
		t.Fatalf("unexpected progress envelope: %#v", event)
	}
	if event.Done != 512 || event.Total != 1024 || event.ElapsedMS != 2000 {
		t.Fatalf("unexpected progress accounting: %#v", event)
	}
	if event.BytesPerSecond != 256 {
		t.Fatalf("bytes_per_second = %d, want 256", event.BytesPerSecond)
	}
	if event.ETASeconds == nil || *event.ETASeconds != 2 {
		t.Fatalf("eta_seconds = %v, want 2", event.ETASeconds)
	}

	complete := makeProgressEvent(drivebackup.Progress{Done: 1024, Total: 1024}, time.Second)
	if complete.ETASeconds != nil {
		t.Fatalf("completed progress must omit ETA: %#v", complete)
	}
}
