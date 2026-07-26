//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/isocapture"
)

func TestRequestedISO(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{args: []string{"--format", "iso"}, want: true},
		{args: []string{"--format=ISO"}, want: true},
		{args: []string{"--format", "vhdx"}, want: false},
		{args: nil, want: false},
	} {
		if got := requestedISO(test.args); got != test.want {
			t.Fatalf("requestedISO(%v)=%t want %t", test.args, got, test.want)
		}
	}
}

func TestNewISOCaptureOptionsBindsReviewedSource(t *testing.T) {
	bindingDigest := strings.Repeat("a", 64)
	contentDigest := strings.Repeat("b", 64)
	progress := func(isocapture.CaptureProgress) {}
	options := newISOCaptureOptions(
		"/dev/sdz",
		"/dev/sdz1",
		isocapture.FilesystemCapturePlan{
			SourceBindingSHA256: bindingDigest,
			SourceContentSHA256: contentDigest,
			VolumeID:            "RUFUS_TEST",
		},
		progress,
	)
	if options.SourceDevicePath != "/dev/sdz" || options.SourceNode != "/dev/sdz1" {
		t.Fatalf("unexpected source binding: %+v", options)
	}
	if options.ExpectedBindingSHA256 != bindingDigest || options.ExpectedContentSHA256 != contentDigest || options.VolumeID != "RUFUS_TEST" {
		t.Fatalf("unexpected reviewed plan binding: %+v", options)
	}
	if options.Progress == nil {
		t.Fatal("progress callback was not preserved")
	}
}

func TestValidateISOPlanBindings(t *testing.T) {
	binding := strings.Repeat("a", 64)
	content := strings.Repeat("b", 64)
	plan := isocapture.FilesystemCapturePlan{SourceBindingSHA256: binding, SourceContentSHA256: content}
	if err := validateISOPlanBindings(plan, binding, content); err != nil {
		t.Fatal(err)
	}
	if err := validateISOPlanBindings(plan, strings.Repeat("c", 64), content); err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("unexpected binding mismatch error: %v", err)
	}
	if err := validateISOPlanBindings(plan, binding, strings.Repeat("d", 64)); err == nil || !strings.Contains(err.Error(), "content changed") {
		t.Fatalf("unexpected content mismatch error: %v", err)
	}
}

func TestRunISOValidatesArgumentsBeforeDeviceAccess(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing-device", args: []string{"--format", "iso"}, want: "--device is required"},
		{name: "missing-output", args: []string{"--format", "iso", "--device", "/dev/missing"}, want: "--output is required"},
		{name: "wrong-format", args: []string{"--format", "raw", "--device", "/dev/missing", "--output", "/tmp/out.iso"}, want: "requires --format iso"},
		{name: "no-unmount", args: []string{"--format", "iso", "--device", "/dev/missing", "--output", "/tmp/out.iso", "--no-unmount"}, want: "not applicable"},
		{name: "yes-bindings", args: []string{"--format", "iso", "--device", "/dev/missing", "--output", "/tmp/out.iso", "--yes"}, want: "requires --expected-identity"},
		{name: "json-interactive", args: []string{"--format", "iso", "--device", "/dev/missing", "--output", "/tmp/out.iso", "--json"}, want: "requires --yes"},
		{name: "progress", args: []string{"--format", "iso", "--device", "/dev/missing", "--output", "/tmp/out.iso", "--progress-json"}, want: "requires non-dry-run --json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runISO(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want text %q", err, test.want)
			}
		})
	}
}

func TestSelectISOSourceRequiresOneMountedFilesystem(t *testing.T) {
	base := device.BlockDevice{Path: "/dev/sdz", Type: "disk"}
	valid := base
	valid.Children = []device.BlockDevice{{Path: "/dev/sdz1", Type: "part", Mountpoints: []string{"/media/USB"}}}
	node, mountpoint, err := selectISOSource(valid)
	if err != nil {
		t.Fatal(err)
	}
	if node.Path != "/dev/sdz1" || mountpoint != "/media/USB" {
		t.Fatalf("node=%+v mount=%q", node, mountpoint)
	}

	for _, test := range []struct {
		name     string
		selected device.BlockDevice
		text     string
	}{
		{name: "not-disk", selected: device.BlockDevice{Path: "/dev/sdz1", Type: "part"}, text: "whole disk"},
		{name: "none", selected: base, text: "found 0"},
		{name: "two", selected: func() device.BlockDevice {
			value := base
			value.Children = []device.BlockDevice{
				{Path: "/dev/sdz1", Type: "part", Mountpoints: []string{"/media/A"}},
				{Path: "/dev/sdz2", Type: "part", Mountpoints: []string{"/media/B"}},
			}
			return value
		}(), text: "found 2"},
		{name: "unsupported", selected: func() device.BlockDevice {
			value := base
			value.Children = []device.BlockDevice{{Path: "/dev/mapper/test", Type: "crypt", Mountpoints: []string{"/media/A"}}}
			return value
		}(), text: "unsupported device type"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := selectISOSource(test.selected)
			if err == nil || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("error=%v want text %q", err, test.text)
			}
		})
	}
}

func TestISOConfirmationPhraseBindsEverySourceIdentity(t *testing.T) {
	got := isoConfirmationPhrase("/dev/sdz", "/dev/sdz1", "/media/USB", "/tmp/capture.iso")
	want := "SAVE FILESYSTEM /dev/sdz1 AT /media/USB ON /dev/sdz TO /tmp/capture.iso"
	if got != want {
		t.Fatalf("phrase=%q want %q", got, want)
	}
}

func TestWriteISOJSONProgress(t *testing.T) {
	var output bytes.Buffer
	progress := isocapture.CaptureProgress{Phase: "master", Done: 512, Total: 1024}
	if err := writeISOJSONProgress(&output, progress, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	var event backupProgress
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Schema != 2 || event.Type != "progress" || event.Phase != "master" || event.Done != 512 || event.Total != 1024 {
		t.Fatalf("unexpected ISO progress: %+v", event)
	}
	if event.BytesPerSecond != 256 || event.ETASeconds == nil || *event.ETASeconds != 2 {
		t.Fatalf("unexpected ISO progress rate: %+v", event)
	}
}
