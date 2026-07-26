//go:build linux

package isocapture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectFilesystemCaptureReturnsDeterministicPlan(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })

	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "EFI"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "EFI", "BOOTAA64.EFI"), []byte("efi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "README.TXT"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "capture.iso")
	plan, err := InspectFilesystemCapture(context.Background(), source, output, "/dev/test-source", "TEST_MEDIA", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != FilesystemCapturePlanSchema || plan.Format != "iso" || plan.Profile != ProfileISO9660JolietUDF || plan.Filesystem != "udf" {
		t.Fatalf("unexpected plan identity: %+v", plan)
	}
	if plan.Provider != "/usr/bin/genisoimage" || plan.VolumeID != "TEST_MEDIA" || plan.SourceDevice != "/dev/test-source" || plan.SourceMount != source || plan.Destination != output {
		t.Fatalf("unexpected plan binding: %+v", plan)
	}
	if plan.Files != 2 || plan.Directories != 1 || plan.SourceBytes != 10 || plan.RequiredBytes <= plan.SourceBytes || plan.AvailableBytes < plan.RequiredBytes {
		t.Fatalf("unexpected plan capacity evidence: %+v", plan)
	}
	if len(plan.SourceBindingSHA256) != 64 || len(plan.SourceContentSHA256) != 64 || len(plan.Limitations) != len(filesystemCaptureLimitations) {
		t.Fatalf("incomplete plan evidence: %+v", plan)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("dry-run created destination: %v", err)
	}
}

func TestInspectFilesystemCaptureLimitationsAreCopied(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "FILE.TXT"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := InspectFilesystemCapture(context.Background(), source, filepath.Join(t.TempDir(), "capture.iso"), "/dev/test-source", "", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	plan.Limitations[0] = "modified"
	if filesystemCaptureLimitations[0] == "modified" {
		t.Fatal("plan limitations alias package policy")
	}
}

func TestInspectFilesystemCaptureRejectsInvalidSource(t *testing.T) {
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })
	for _, test := range []struct {
		name   string
		source string
		text   string
	}{
		{name: "relative", source: "source", text: "absolute"},
		{name: "root", source: "/", text: "non-root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := InspectFilesystemCapture(context.Background(), test.source, filepath.Join(t.TempDir(), "capture.iso"), "/dev/test", "", Limits{})
			if err == nil || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("error=%v want text %q", err, test.text)
			}
		})
	}
}
