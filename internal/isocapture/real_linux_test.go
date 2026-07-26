//go:build linux

package isocapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	for _, utility := range []string{"genisoimage", "losetup", "mkfs.ext4", "mount"} {
		if _, err := exec.LookPath(utility); err != nil {
			t.Skipf("%s is unavailable", utility)
		}
	}

	backingPath := filepath.Join(t.TempDir(), "source.ext4")
	backing, err := os.OpenFile(backingPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := backing.Truncate(64 * 1024 * 1024); err != nil {
		backing.Close()
		t.Fatal(err)
	}
	if err := backing.Close(); err != nil {
		t.Fatal(err)
	}
	loopDevice := strings.TrimSpace(runRealISOCommand(t, "losetup", "--find", "--show", "--", backingPath))
	if !strings.HasPrefix(loopDevice, "/dev/loop") {
		t.Fatalf("losetup returned unexpected device %q", loopDevice)
	}
	defer func() {
		if output, err := exec.Command("losetup", "--detach", loopDevice).CombinedOutput(); err != nil {
			t.Errorf("detach source loop device: %v: %s", err, strings.TrimSpace(string(output)))
		}
	}()
	runRealISOCommand(t, "mkfs.ext4", "-F", "-q", "-L", "RUFUS_SRC", "--", loopDevice)

	sourcePath := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	runRealISOCommand(t, "mount", "--internal-only", "--no-canonicalize", "--no-mtab", "-t", "ext4", "-o", "rw,nosuid,nodev,noexec", "--", loopDevice, sourcePath)
	mounted := true
	defer func() {
		if !mounted {
			return
		}
		if err := syscallUnmount(sourcePath); err != nil {
			t.Errorf("unmount source filesystem: %v", err)
		}
	}()
	if err := os.Remove(filepath.Join(sourcePath, "lost+found")); err != nil {
		t.Fatal(err)
	}
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
	if err := syncFilesystem(sourcePath); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	outputPath := filepath.Join(t.TempDir(), "rufus-test.iso")
	plan, err := InspectFilesystemCapture(ctx, sourcePath, outputPath, loopDevice, "RUFUS_TEST", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	options := FilesystemCaptureOptions{
		SourceDevicePath:      loopDevice,
		SourceNode:            loopDevice,
		ExpectedBindingSHA256: plan.SourceBindingSHA256,
		ExpectedContentSHA256: plan.SourceContentSHA256,
		VolumeID:              plan.VolumeID,
	}
	report, err := CaptureFilesystem(ctx, sourcePath, outputPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != CapturePassed || !report.SourceStable || !report.UDFValidated || !report.Published {
		t.Fatalf("unexpected filesystem capture evidence: %+v", report)
	}
	if report.SourceDevice != loopDevice || report.SourceNode != loopDevice || report.SourceMount != sourcePath {
		t.Fatalf("capture source binding differs from loop filesystem: %+v", report)
	}
	if report.SourceContentSHA256 != plan.SourceContentSHA256 || report.SourceBytes != plan.SourceBytes || report.RequiredBytes != plan.RequiredBytes {
		t.Fatalf("capture evidence differs from reviewed plan: plan=%+v report=%+v", plan, report)
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

	second, err := CaptureFilesystem(ctx, sourcePath, outputPath, options)
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

	if err := syscallUnmount(sourcePath); err != nil {
		t.Fatal(err)
	}
	mounted = false
}

func runRealISOCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Env = []string{
		"HOME=/nonexistent",
		"LC_ALL=C.UTF-8",
		"LIBMOUNT_FSTAB=/dev/null",
		"LIBMOUNT_FORCE_MOUNT2=always",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String()
}

func syscallUnmount(path string) error {
	command := exec.Command("umount", "--", path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func syncFilesystem(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync source filesystem: %w", err)
	}
	return nil
}

func makeSparseFixture() []byte {
	data := make([]byte, 2*1024*1024)
	copy(data[:4096], []byte("first extent"))
	copy(data[len(data)/2:len(data)/2+4096], []byte("middle extent"))
	copy(data[len(data)-4096:], []byte("last extent"))
	return data
}
