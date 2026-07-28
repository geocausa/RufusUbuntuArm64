//go:build linux

package linuxmedia

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreateExtractedOnRealLoopDevice(t *testing.T) {
	if os.Getenv("RUFUS_REAL_EXTRACTED_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EXTRACTED_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real ISO Image mode loop test requires root")
	}
	for _, tool := range []string{
		"losetup", "blockdev", "genisoimage", "mount", "umount", "findmnt",
		"lsblk", "wipefs", "sync", "mkfs.vfat", "fsck.vfat", "blkid",
	} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required loop-test tool %q is unavailable: %v", tool, err)
		}
	}

	sourceRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(sourceRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x61))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "vmlinuz"), "loop-kernel")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "initrd"), "loop-initrd")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "filesystem.squashfs"), strings.Repeat("verified-payload-", 4096))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "README.txt"), "RufusArm64 real ISO Image mode loop qualification\n")

	isoPath := filepath.Join(t.TempDir(), "linux-arm64.iso")
	output, err := exec.Command("genisoimage", "-quiet", "-J", "-R", "-V", "RUFUSISO", "-o", isoPath, sourceRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("create source ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}

	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(t.TempDir(), "target.img")
	backingFile, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := backingFile.Truncate(capacity); err != nil {
		_ = backingFile.Close()
		t.Fatal(err)
	}
	if err := backingFile.Close(); err != nil {
		t.Fatal(err)
	}

	loopPath := attachExtractedLoop(t, backing)
	mountRoot := filepath.Join(t.TempDir(), "mounted")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mounted := false
	t.Cleanup(func() {
		if mounted {
			_, _ = exec.Command("umount", "--", mountRoot).CombinedOutput()
		}
		if loopPath != "" {
			_, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput()
		}
	})
	waitForExtractedLoopFlock(t, loopPath)

	deviceID, err := safety.KernelDeviceID(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	sizeOutput, err := exec.Command("blockdev", "--getsize64", loopPath).CombinedOutput()
	if err != nil {
		t.Fatalf("read loop capacity: %v: %s", err, strings.TrimSpace(string(sizeOutput)))
	}
	targetSize, err := strconv.ParseUint(strings.TrimSpace(string(sizeOutput)), 10, 64)
	if err != nil || targetSize != uint64(capacity) {
		t.Fatalf("unexpected loop capacity %q: %v", strings.TrimSpace(string(sizeOutput)), err)
	}

	beforeCalls := 0
	result, err := CreateExtracted(context.Background(), resolvedISO, loopPath, ExtractedCreateOptions{
		TargetSize:       targetSize,
		ExpectedDeviceID: deviceID,
		ExpectedSource:   sourceIdentity,
		Architecture:     "arm64",
		VolumeLabel:      "RUFUS-LIVE",
		BeforeDestructive: func(_ *os.File) error {
			beforeCalls++
			open, err := safety.OpenReopenableDevice(loopPath)
			if err != nil {
				return err
			}
			defer open.Close()
			return safety.VerifyOpenDevice(open, deviceID, targetSize)
		},
	}, nil)
	if err != nil {
		t.Fatalf("create ISO Image mode loop media: %v; result=%+v", err, result)
	}
	if beforeCalls != 1 {
		t.Fatalf("before-destructive calls=%d, want 1", beforeCalls)
	}
	if result.Manifest.Files < 6 || result.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" || len(result.SourceSHA256) != 64 {
		t.Fatalf("unexpected ISO Image mode result: %+v", result)
	}

	// Reopen the completed backing image as a new loop device. This verifies the
	// durable artifact independently of the writer's live descriptors and avoids
	// trusting a stale partition node after in-place MBR replacement.
	if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("detach completed ISO Image mode target: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath = ""
	loopPath = attachExtractedLoop(t, backing)
	waitForExtractedLoopFlock(t, loopPath)

	partitionPath, err := waitExtractedLoopPartition(loopPath, result.Layout.Partition, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blkidOutput, err := exec.Command("blkid", "-p", "-o", "export", partitionPath).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect completed FAT32 partition: %v: %s", err, strings.TrimSpace(string(blkidOutput)))
	}
	metadata := string(blkidOutput)
	if !strings.Contains(metadata, "TYPE=vfat") || !strings.Contains(metadata, "LABEL=RUFUS-LIVE") {
		t.Fatalf("unexpected completed filesystem metadata:\n%s", metadata)
	}

	output, err = exec.Command("mount", "-t", "vfat", "-o", "ro,nosuid,nodev,noexec", "--", partitionPath, mountRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("mount completed ISO Image mode media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = true
	for relative, expected := range map[string]string{
		"README.txt":         "RufusArm64 real ISO Image mode loop qualification\n",
		"casper/vmlinuz":     "loop-kernel",
		"boot/grub/grub.cfg": "linux /casper/vmlinuz boot=casper --- quiet\n",
	} {
		data, err := os.ReadFile(filepath.Join(mountRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read copied path %s: %v", relative, err)
		}
		if string(data) != expected {
			t.Fatalf("copied path %s mismatch: %q", relative, data)
		}
	}
	if info, err := os.Stat(filepath.Join(mountRoot, "EFI", "BOOT", "BOOTAA64.EFI")); err != nil || info.Size() == 0 {
		t.Fatalf("fallback UEFI loader is missing or empty: %v", err)
	}
	if output, err := exec.Command("umount", "--", mountRoot).CombinedOutput(); err != nil {
		t.Fatalf("unmount completed media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = false
}

func attachExtractedLoop(t *testing.T, backing string) string {
	t.Helper()
	output, err := exec.Command("losetup", "--find", "--show", "--partscan", backing).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	path := strings.TrimSpace(string(output))
	if !strings.HasPrefix(path, "/dev/loop") {
		t.Fatalf("unexpected loop path %q", path)
	}
	return path
}

func waitForExtractedLoopFlock(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err == nil {
			err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return
			}
			_ = file.Close()
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("loop device %s did not become flockable: %v", path, lastErr)
}

func waitExtractedLoopPartition(loopPath string, layout PartitionLayout, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		path := persistentPartitionPath(loopPath, layout.Number)
		if persistentPartitionMatches(path, layout) {
			return path, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("ISO Image mode loop partition did not appear with expected geometry")
}
