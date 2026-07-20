//go:build linux

package nonbootable

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

func TestExecuteDeviceFormatsRealLoopDevices(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise real loop devices")
	}
	if os.Geteuid() != 0 {
		t.Skip("real formatter loop tests require root")
	}
	for _, tool := range []string{
		"losetup", "blockdev", "sfdisk", "wipefs", "blkid",
		"mkfs.vfat", "fsck.vfat", "mkfs.exfat", "fsck.exfat",
		"mkfs.ntfs", "ntfsfix", "mkfs.ext4", "e2fsck",
	} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required loop-test tool %q is unavailable: %v", tool, err)
		}
	}

	tests := []struct {
		name       string
		scheme     string
		filesystem string
		label      string
	}{
		{name: "gpt-fat32", scheme: SchemeGPT, filesystem: FilesystemFAT32, label: "RUFUSFAT"},
		{name: "mbr-exfat", scheme: SchemeMBR, filesystem: FilesystemExFAT, label: "RUFUS-EXFAT"},
		{name: "gpt-ntfs", scheme: SchemeGPT, filesystem: FilesystemNTFS, label: "RUFUS-NTFS"},
		{name: "mbr-ext4", scheme: SchemeMBR, filesystem: FilesystemExt4, label: "RUFUS-EXT4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const capacity = 256 * 1024 * 1024
			backing := filepath.Join(t.TempDir(), test.name+".img")
			file, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(capacity); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			output, err := exec.Command("losetup", "--find", "--show", "--partscan", backing).CombinedOutput()
			if err != nil {
				t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
			}
			loopPath := strings.TrimSpace(string(output))
			t.Cleanup(func() {
				_, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput()
			})
			if !strings.HasPrefix(loopPath, "/dev/loop") {
				t.Fatalf("unexpected loop path %q", loopPath)
			}
			waitForFormatterLoopLock(t, loopPath)

			deviceID, err := safety.KernelDeviceID(loopPath)
			if err != nil {
				t.Fatal(err)
			}
			sectorOutput, err := exec.Command("blockdev", "--getss", loopPath).CombinedOutput()
			if err != nil {
				t.Fatalf("read logical sector size: %v: %s", err, strings.TrimSpace(string(sectorOutput)))
			}
			sectorSize, err := strconv.ParseUint(strings.TrimSpace(string(sectorOutput)), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := BuildPlan(Request{
				DevicePath:        loopPath,
				ExpectedIdentity:  strings.Repeat("a", 64),
				DeviceSizeBytes:   capacity,
				LogicalSectorSize: sectorSize,
				Scheme:            test.scheme,
				Filesystem:        test.filesystem,
				Label:             test.label,
			})
			if err != nil {
				t.Fatal(err)
			}
			beforeCalls := 0
			report, err := ExecuteDevice(context.Background(), plan, DeviceOptions{
				ExpectedDeviceID: deviceID,
				ExpectedSize:     capacity,
				BeforeDestructive: func(open *os.File) error {
					beforeCalls++
					return safety.VerifyOpenDevice(open, deviceID, capacity)
				},
			})
			if err != nil {
				t.Fatalf("format %s: %v; report=%+v", test.name, err, report)
			}
			if beforeCalls != 1 {
				t.Fatalf("before-destructive calls=%d, want 1", beforeCalls)
			}
			if report.Status != StatusPassed || report.Filesystem == nil || !report.Reusable || report.Bootable {
				t.Fatalf("unexpected formatter report: %+v", report)
			}
			if report.Filesystem.Type != test.filesystem || report.Filesystem.Label != plan.Label || report.Filesystem.ParentPath != loopPath {
				t.Fatalf("filesystem readback mismatch: %+v", report.Filesystem)
			}
			if err := ValidateReport(report); err != nil {
				t.Fatalf("real formatter report rejected: %v", err)
			}
		})
	}
}

func waitForFormatterLoopLock(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		file, err := os.OpenFile(path, os.O_RDWR|syscallOpenFlags(), 0)
		if err == nil {
			_ = file.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("loop device %s did not become exclusively openable: %v", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func syscallOpenFlags() int {
	return 0x80 | 0x20000 // O_EXCL | O_NOFOLLOW on Linux.
}
