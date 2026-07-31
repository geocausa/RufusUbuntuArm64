//go:build linux

package linuxmedia

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
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

func TestCreateExtractedNTFSOnRealLoopDeviceMBR(t *testing.T) {
	testCreateExtractedNTFSOnRealLoopDevice(t, "mbr", "Rufus:*?-Été-MBR")
}

func TestCreateExtractedNTFSOnRealLoopDeviceGPT(t *testing.T) {
	testCreateExtractedNTFSOnRealLoopDevice(t, "gpt", "Rufus:*?-Été-GPT")
}

func testCreateExtractedNTFSOnRealLoopDevice(t *testing.T, scheme, label string) {
	t.Helper()
	if os.Getenv("RUFUS_REAL_EXTRACTED_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EXTRACTED_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real NTFS ISO Image mode loop test requires root")
	}
	for _, tool := range []string{
		"losetup", "blockdev", "genisoimage", "mount", "umount", "findmnt",
		"lsblk", "wipefs", "sync", "mkfs.ntfs", "ntfsfix", "blkid", "cmp",
	} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required NTFS loop-test tool %q is unavailable: %v", tool, err)
		}
	}
	if scheme == "gpt" {
		if _, err := exec.LookPath("sgdisk"); err != nil {
			t.Fatalf("required GPT verification tool sgdisk is unavailable: %v", err)
		}
	}
	asset, err := uefintfs.Locate()
	if err != nil {
		t.Fatalf("locate pinned UEFI:NTFS asset: %v", err)
	}

	sourceRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(sourceRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x91))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "vmlinuz"), scheme+"-ntfs-loop-kernel")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "initrd"), scheme+"-ntfs-loop-initrd")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "filesystem.squashfs"), strings.Repeat("verified-ntfs-payload-", 4096))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "README.txt"), "RufusArm64 "+strings.ToUpper(scheme)+" NTFS ISO Image mode qualification\n")

	isoPath := filepath.Join(t.TempDir(), "linux-arm64-"+scheme+"-ntfs.iso")
	output, err := exec.Command("genisoimage", "-quiet", "-J", "-R", "-V", "RUFUSNTFS", "-o", isoPath, sourceRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("create source ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}

	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(t.TempDir(), "target-"+scheme+"-ntfs.img")
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
	mountRoot := filepath.Join(t.TempDir(), "mounted-"+scheme+"-ntfs")
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
	result, err := CreateExtractedNTFS(context.Background(), resolvedISO, loopPath, ExtractedCreateOptions{
		TargetSize:       targetSize,
		ExpectedDeviceID: deviceID,
		ExpectedSource:   sourceIdentity,
		Architecture:     "arm64",
		VolumeLabel:      label,
		PartitionScheme:  scheme,
		ClusterSize:      4096,
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
		t.Fatalf("create %s NTFS ISO Image mode loop media: %v; result=%+v", scheme, err, result)
	}
	if beforeCalls != 1 {
		t.Fatalf("before-destructive calls=%d, want 1", beforeCalls)
	}
	if result.Plan.PartitionScheme != scheme || result.Plan.FilesystemSelection.Selected != ExtractedFilesystemNTFS ||
		result.Plan.Boot == nil || result.UEFINTFSSHA256 != uefintfs.ImageSHA256 || result.UEFINTFSSize != uefintfs.ImageSize {
		t.Fatalf("unexpected NTFS ISO Image mode result: %+v", result)
	}

	// Detach and reopen the completed backing image so all verification below is
	// independent of the writer's live descriptors and partition nodes.
	if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("detach completed %s NTFS target: %v: %s", scheme, err, strings.TrimSpace(string(output)))
	}
	loopPath = ""
	loopPath = attachExtractedLoop(t, backing)
	waitForExtractedLoopFlock(t, loopPath)

	dataPartitionPath, err := waitExtractedLoopPartition(loopPath, result.Plan.Data, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bootPartitionPath, err := waitExtractedLoopPartition(loopPath, *result.Plan.Boot, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if scheme == "gpt" {
		verifyOutput, verifyErr := exec.Command("sgdisk", "--verify", loopPath).CombinedOutput()
		if verifyErr != nil {
			t.Fatalf("verify reopened GPT metadata: %v: %s", verifyErr, strings.TrimSpace(string(verifyOutput)))
		}
		if !strings.Contains(string(verifyOutput), "No problems found") {
			t.Fatalf("unexpected GPT verification output:\n%s", verifyOutput)
		}
	}

	blkidOutput, err := waitForExtractedBlkid(dataPartitionPath, true, 10*time.Second)
	if err != nil {
		t.Fatalf("inspect completed NTFS partition: %v", err)
	}
	metadata := string(blkidOutput)
	if !strings.Contains(metadata, "TYPE=ntfs") || !strings.Contains(metadata, "LABEL="+label) {
		t.Fatalf("unexpected completed NTFS metadata:\n%s", metadata)
	}
	if err := uefintfs.VerifyPartitionPath(bootPartitionPath, asset); err != nil {
		t.Fatalf("compare reopened UEFI:NTFS boot partition: %v", err)
	}

	output, err = waitForExtractedReadOnlyMount(dataPartitionPath, mountRoot, "", 10*time.Second)
	if err != nil {
		t.Fatalf("mount completed %s NTFS media: %v: %s", scheme, err, strings.TrimSpace(string(output)))
	}
	mounted = true
	for relative, expected := range map[string]string{
		"README.txt":         "RufusArm64 " + strings.ToUpper(scheme) + " NTFS ISO Image mode qualification\n",
		"casper/vmlinuz":     scheme + "-ntfs-loop-kernel",
		"boot/grub/grub.cfg": "linux /casper/vmlinuz boot=casper --- quiet\n",
	} {
		data, err := os.ReadFile(filepath.Join(mountRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read copied NTFS path %s: %v", relative, err)
		}
		if string(data) != expected {
			t.Fatalf("copied NTFS path %s mismatch: %q", relative, data)
		}
	}
	if info, err := os.Stat(filepath.Join(mountRoot, "EFI", "BOOT", "BOOTAA64.EFI")); err != nil || info.Size() == 0 {
		t.Fatalf("fallback UEFI loader is missing or empty: %v", err)
	}
	if output, err := exec.Command("umount", "--", mountRoot).CombinedOutput(); err != nil {
		t.Fatalf("unmount completed %s NTFS media: %v: %s", scheme, err, strings.TrimSpace(string(output)))
	}
	mounted = false
}
