//go:build linux

package isocapture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealGenISOImageUDFRoundTrip(t *testing.T) {
	if os.Getenv("RUFUS_REAL_ISO_CAPTURE_TEST") != "1" {
		t.Skip("set RUFUS_REAL_ISO_CAPTURE_TEST=1 to exercise real UDF mastering and validation")
	}
	if os.Geteuid() != 0 {
		t.Skip("real UDF mastering qualification requires root")
	}
	for _, utility := range []string{"genisoimage", "mount"} {
		if _, err := exec.LookPath(utility); err != nil {
			t.Skipf("%s is unavailable", utility)
		}
	}

	sourcePath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourcePath, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string][]byte{
		filepath.Join(sourcePath, "EFI", "BOOT", "BOOTAA64.EFI"): []byte("deterministic-arm64-efi-fixture"),
		filepath.Join(sourcePath, "README.TXT"):                  []byte("snapshot-bound UDF capture\n"),
		filepath.Join(sourcePath, "PAYLOAD.BIN"):                 makeSparseFixture(),
	}
	for path, content := range fixtures {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	output, err := os.CreateTemp(t.TempDir(), "private-*.iso")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := output.Chmod(0o600); err != nil {
		t.Fatal(err)
	}

	capture, err := Master(context.Background(), source, output, MasterOptions{VolumeID: "RUFUS_TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if capture.Status != CapturePassed || !capture.SourceStable || capture.OutputBytes == 0 || capture.OutputBytes > capture.MaximumOutputBytes {
		t.Fatalf("unexpected mastering evidence: %+v", capture)
	}
	validation, err := VerifyImage(
		context.Background(),
		output,
		capture.SourceContentSHA256,
		capture.OutputSHA256,
		capture.OutputBytes,
		ValidationOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if validation.Status != CapturePassed || validation.MountedContentSHA256 != capture.SourceContentSHA256 || validation.ImageSHA256 != capture.OutputSHA256 {
		t.Fatalf("unexpected validation evidence: capture=%+v validation=%+v", capture, validation)
	}
	if validation.Files != capture.Files || validation.Directories != capture.Directories || validation.ContentBytes != capture.SourceBytes {
		t.Fatalf("mounted inventory differs: capture=%+v validation=%+v", capture, validation)
	}
}

func makeSparseFixture() []byte {
	data := make([]byte, 2*1024*1024)
	copy(data[:4096], []byte("first extent"))
	copy(data[len(data)/2:len(data)/2+4096], []byte("middle extent"))
	copy(data[len(data)-4096:], []byte("last extent"))
	return data
}
