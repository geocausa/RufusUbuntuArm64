//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/safety"
)

func TestCaptureDeviceExportsVerifiedContainersFromRealReadOnlyLoop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real loop-device backup requires root")
	}
	for _, utility := range []string{"losetup", "blockdev", "qemu-img"} {
		if _, err := exec.LookPath(utility); err != nil {
			t.Skipf("%s is unavailable", utility)
		}
	}

	const size = 8 * 1024 * 1024
	data := make([]byte, size)
	copy(data[:4096], bytes.Repeat([]byte{0x11}, 4096))
	copy(data[size/2:size/2+4096], bytes.Repeat([]byte{0x5a}, 4096))
	copy(data[size-4096:], bytes.Repeat([]byte{0xee}, 4096))
	expectedHash := sha256.Sum256(data)
	expectedDigest := hex.EncodeToString(expectedHash[:])

	backing := filepath.Join(t.TempDir(), "source-loop.img")
	if err := os.WriteFile(backing, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("losetup", "--find", "--show", "--read-only", backing).CombinedOutput()
	if err != nil {
		t.Fatalf("attach read-only loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	if !strings.HasPrefix(loopPath, "/dev/loop") {
		t.Fatalf("losetup returned unexpected path %q", loopPath)
	}
	t.Cleanup(func() {
		if detachOutput, detachErr := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); detachErr != nil {
			t.Logf("detach %s: %v: %s", loopPath, detachErr, strings.TrimSpace(string(detachOutput)))
		}
	})
	if _, err := exec.LookPath("udevadm"); err == nil {
		if settleOutput, settleErr := exec.Command("udevadm", "settle").CombinedOutput(); settleErr != nil {
			t.Logf("udevadm settle: %v: %s", settleErr, strings.TrimSpace(string(settleOutput)))
		}
	}

	deviceID, err := safety.KernelDeviceID(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	capacityOutput, err := exec.Command("blockdev", "--getsize64", loopPath).CombinedOutput()
	if err != nil {
		t.Fatalf("read loop capacity: %v: %s", err, strings.TrimSpace(string(capacityOutput)))
	}
	capacity, err := strconv.ParseUint(strings.TrimSpace(string(capacityOutput)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if capacity != size {
		t.Fatalf("loop capacity = %d, want %d", capacity, size)
	}
	waitForReadOnlyLoopExclusive(t, loopPath)

	for _, format := range []Format{FormatVHD, FormatVHDX} {
		t.Run(string(format), func(t *testing.T) {
			destinationDir := t.TempDir()
			destination := filepath.Join(destinationDir, "captured"+format.Extension())
			measure, err := MeasureContainer(context.Background(), capacity, format)
			if err != nil {
				t.Fatal(err)
			}
			var phases = make(map[string]bool)
			report, err := CaptureDevice(context.Background(), loopPath, destination, DeviceOptions{
				ExpectedDeviceID: deviceID,
				ExpectedSize:     capacity,
				Format:           format,
				Progress: func(progress Progress) {
					if progress.Phase != "" {
						phases[progress.Phase] = true
					}
				},
				BeforeRead: func(open *os.File) error {
					return safety.VerifyOpenDevice(open, deviceID, capacity)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if report.Schema != ReportSchema || report.Status != StatusPassed || report.Format != format {
				t.Fatalf("unexpected report: %+v", report)
			}
			if report.PlannedBytes != capacity || report.CompletedBytes != capacity {
				t.Fatalf("unexpected source accounting: %+v", report)
			}
			if report.SHA256 != expectedDigest || report.SourceSHA256 != expectedDigest {
				t.Fatalf("source digest evidence=%+v want %s", report, expectedDigest)
			}
			if len(report.OutputSHA256) != 64 || report.OutputBytes == 0 || report.ContentComparison != ComparisonPassed {
				t.Fatalf("incomplete output evidence: %+v", report)
			}
			if report.OutputBytes > measure.FullyAllocatedBytes {
				t.Fatalf("container output bytes = %d, exceeds admitted bound %d", report.OutputBytes, measure.FullyAllocatedBytes)
			}
			if format == FormatVHD && report.Consistency != ConsistencyUnsupported {
				t.Fatalf("VHD consistency=%q", report.Consistency)
			}
			if format == FormatVHDX && report.Consistency != ConsistencyPassed {
				t.Fatalf("VHDX consistency=%q", report.Consistency)
			}
			for _, phase := range []string{"hash_source", "convert", "hash_output"} {
				if !phases[phase] {
					t.Fatalf("missing %s progress in %v", phase, phases)
				}
			}
			info, err := os.Stat(destination)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || uint64(info.Size()) != report.OutputBytes {
				t.Fatalf("published destination=%v report=%+v", info, report)
			}
			partials, err := filepath.Glob(filepath.Join(destinationDir, ".captured"+format.Extension()+".rufusarm64-partial-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials) != 0 {
				t.Fatalf("temporary outputs remain: %v", partials)
			}
		})
	}
}
