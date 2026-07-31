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
)

func TestCreateExtractedOnRealLoopDeviceGPT(t *testing.T) {
	if os.Getenv("RUFUS_REAL_EXTRACTED_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EXTRACTED_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real ISO Image mode loop test requires root")
	}
	sourceRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(sourceRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x71))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "vmlinuz"), "gpt-loop-kernel")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "initrd"), "gpt-loop-initrd")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "README.txt"), "RufusArm64 GPT ISO Image mode qualification\n")

	isoPath := filepath.Join(t.TempDir(), "linux-arm64-gpt.iso")
	output, err := exec.Command("genisoimage", "-quiet", "-J", "-R", "-V", "RUFUSGPT", "-o", isoPath, sourceRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("create source ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}

	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(t.TempDir(), "target-gpt.img")
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
	mountRoot := filepath.Join(t.TempDir(), "mounted-gpt")
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

	result, err := CreateExtracted(context.Background(), resolvedISO, loopPath, ExtractedCreateOptions{
		TargetSize:       targetSize,
		ExpectedDeviceID: deviceID,
		ExpectedSource:   sourceIdentity,
		Architecture:     "arm64",
		VolumeLabel:      "RUFUS-GPT",
		PartitionScheme:  "gpt",
		ClusterSize:      8192,
		BeforeDestructive: func(_ *os.File) error {
			open, err := safety.OpenReopenableDevice(loopPath)
			if err != nil {
				return err
			}
			defer open.Close()
			return safety.VerifyOpenDevice(open, deviceID, targetSize)
		},
	}, nil)
	if err != nil {
		t.Fatalf("create GPT ISO Image mode loop media: %v; result=%+v", err, result)
	}
	if result.PartitionScheme != "gpt" || result.ClusterSize != 8192 {
		t.Fatalf("unexpected selected layout evidence: %+v", result)
	}

	if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("detach completed target: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath = ""
	loopPath = attachExtractedLoop(t, backing)
	waitForExtractedLoopFlock(t, loopPath)
	partitionPath, err := waitExtractedLoopPartition(loopPath, result.Layout.Partition, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blkidOutput, err := waitForExtractedBlkid(partitionPath, false, 10*time.Second)
	if err != nil {
		t.Fatalf("inspect completed FAT32 partition: %v", err)
	}
	metadata := string(blkidOutput)
	if !strings.Contains(metadata, "TYPE=vfat") || !strings.Contains(metadata, "LABEL=RUFUS-GPT") {
		t.Fatalf("unexpected completed filesystem metadata:\n%s", metadata)
	}
	output, err = waitForExtractedReadOnlyMount(partitionPath, mountRoot, "vfat", 10*time.Second)
	if err != nil {
		t.Fatalf("mount completed GPT media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = true
	data, err := os.ReadFile(filepath.Join(mountRoot, "README.txt"))
	if err != nil || string(data) != "RufusArm64 GPT ISO Image mode qualification\n" {
		t.Fatalf("copied GPT media mismatch: %q %v", data, err)
	}
	if output, err := exec.Command("umount", "--", mountRoot).CombinedOutput(); err != nil {
		t.Fatalf("unmount completed GPT media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = false
}
