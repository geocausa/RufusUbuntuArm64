//go:build linux

package isocapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	outputPath := filepath.Join(t.TempDir(), "rufus-test.iso")
	report, err := CaptureFilesystem(context.Background(), sourcePath, outputPath, FilesystemCaptureOptions{
		SourceDevicePath: "/dev/rufus-test-source",
		VolumeID:         "RUFUS_TEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != CapturePassed || !report.SourceStable || !report.UDFValidated || !report.Published {
		t.Fatalf("unexpected filesystem capture evidence: %+v", report)
	}
	if report.ContentComparison != ContentComparisonPassed || report.OutputBytes == 0 || report.OutputBytes > report.RequiredBytes {
		t.Fatalf("invalid output evidence: %+v", report)
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != report.OutputBytes {
		t.Fatalf("published ISO metadata differs: info=%+v report=%+v", info, report)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != report.OutputSHA256 {
		t.Fatalf("published ISO digest differs from report: %x != %s", digest, report.OutputSHA256)
	}

	second, err := CaptureFilesystem(context.Background(), sourcePath, outputPath, FilesystemCaptureOptions{
		SourceDevicePath: "/dev/rufus-test-source",
		VolumeID:         "RUFUS_TEST",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second capture report=%+v error=%v", second, err)
	}
	after, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest := sha256.Sum256(after)
	if afterDigest != digest {
		t.Fatal("failed second capture modified the published ISO")
	}
	partials, err := filepath.Glob(filepath.Join(filepath.Dir(outputPath), ".rufus-test.iso.rufusarm64-partial-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 0 {
		t.Fatalf("partial ISO files survived: %v", partials)
	}
}

func makeSparseFixture() []byte {
	data := make([]byte, 2*1024*1024)
	copy(data[:4096], []byte("first extent"))
	copy(data[len(data)/2:len(data)/2+4096], []byte("middle extent"))
	copy(data[len(data)-4096:], []byte("last extent"))
	return data
}
