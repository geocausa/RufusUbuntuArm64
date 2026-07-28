//go:build linux

package linuxmedia

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreateISOImageOnRealLoopDevice(t *testing.T) {
	if os.Getenv("RUFUS_REAL_ISO_IMAGE_TEST") != "1" {
		t.Skip("set RUFUS_REAL_ISO_IMAGE_TEST=1 to exercise a real loop device")
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

	root := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(root, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x61))
	writeLinuxTestFile(t, filepath.Join(root, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	writeLinuxTestFile(t, filepath.Join(root, "casper", "vmlinuz"), "loop-kernel")
	writeLinuxTestFile(t, filepath.Join(root, "casper", "initrd"), "loop-initrd")
	writeLinuxTestFile(t, filepath.Join(root, "casper", "filesystem.squashfs"), strings.Repeat("verified-payload-", 4096))
	writeLinuxTestFile(t, filepath.Join(root, "README.txt"), "RufusArm64 real ISO Image mode loop qualification\n")

	isoPath := filepath.Join(t.TempDir(), "linux-arm64.iso")
	output, err := exec.Command("genisoimage", "-quiet", "-J", "-R", "-V", "RUFUSISO", "-o", isoPath, root).CombinedOutput()
	if err != nil {
		t.Fatalf("create source ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	patchTestISOHybridMBR(t, isoPath)
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}

	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(t.TempDir(), "target.img")
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

	output, err = exec.Command("losetup", "--find", "--show", "--partscan", backing).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	if !strings.HasPrefix(loopPath, "/dev/loop") {
		t.Fatalf("unexpected loop path %q", loopPath)
	}
	mountRoot := filepath.Join(t.TempDir(), "mounted")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mounted := false
	t.Cleanup(func() {
		if mounted {
			_, _ = exec.Command("umount", "--", mountRoot).CombinedOutput()
		}
		_, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput()
	})

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
	result, err := CreateISOImage(context.Background(), resolvedISO, loopPath, ISOImageCreateOptions{
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

	partitionPath, err := waitISOImageLoopPartition(loopPath, result.Layout.Partition, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blkidOutput, err := exec.Command("blkid", "-o", "export", partitionPath).CombinedOutput()
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
		"README.txt":                 "RufusArm64 real ISO Image mode loop qualification\n",
		"casper/vmlinuz":             "loop-kernel",
		"boot/grub/grub.cfg":         "linux /casper/vmlinuz boot=casper --- quiet\n",
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

func patchTestISOHybridMBR(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	sectors := uint64(info.Size()+511) / 512
	if sectors <= 1 || sectors-1 > uint64(^uint32(0)) {
		t.Fatalf("test ISO has unsupported size %d", info.Size())
	}
	mbr := make([]byte, 512)
	entry := mbr[446:462]
	entry[0] = 0x80
	entry[4] = 0x0c
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], uint32(sectors-1))
	mbr[510] = 0x55
	mbr[511] = 0xaa
	if _, err := file.WriteAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}

func waitISOImageLoopPartition(loopPath string, layout PartitionLayout, timeout time.Duration) (string, error) {
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
