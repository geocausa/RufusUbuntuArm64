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

func TestPrepareExtractedManifestFromRealElToritoFATImage(t *testing.T) {
	if os.Getenv("RUFUS_REAL_EL_TORITO_OVERLAY_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EL_TORITO_OVERLAY_TEST=1 for privileged loop-mount qualification")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real El Torito overlay qualification requires root")
	}
	for _, name := range []string{"genisoimage", "mkfs.vfat", "mcopy", "mmd", "mount", "umount", "findmnt"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is unavailable: %v", name, err)
		}
	}
	root := t.TempDir()
	isoTree := filepath.Join(root, "iso-tree")
	if err := os.MkdirAll(filepath.Join(isoTree, "casper"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isoTree, "casper", "vmlinuz"), []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	bootImage := filepath.Join(isoTree, "efi.img")
	file, err := os.OpenFile(bootImage, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(8 * 1024 * 1024); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runRealLinuxTest(t, "mkfs.vfat", "-F", "32", bootImage)
	runRealLinuxTest(t, "mmd", "-i", bootImage, "::/EFI", "::/EFI/BOOT")
	loader := filepath.Join(root, "BOOTAA64.EFI")
	if err := os.WriteFile(loader, linuxTestARM64EFI(0xa1), 0o644); err != nil {
		t.Fatal(err)
	}
	runRealLinuxTest(t, "mcopy", "-i", bootImage, loader, "::/EFI/BOOT/BOOTAA64.EFI")
	isoPath := filepath.Join(root, "eltorito.iso")
	runRealLinuxTest(t, "genisoimage", "-quiet", "-R", "-J", "-V", "ELTORITO_TEST", "-eltorito-alt-boot", "-e", "efi.img", "-no-emul-boot", "-o", isoPath, isoTree)

	isoMount := filepath.Join(root, "iso-mount")
	if err := os.Mkdir(isoMount, 0o700); err != nil {
		t.Fatal(err)
	}
	runRealLinuxTest(t, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", isoPath, isoMount)
	defer func() { _ = exec.Command("umount", "--", isoMount).Run() }()
	if _, err := os.Stat(filepath.Join(isoMount, "EFI", "BOOT", "BOOTAA64.EFI")); !os.IsNotExist(err) {
		t.Fatalf("fixture unexpectedly exposes fallback in ISO tree: %v", err)
	}
	isoFile, err := os.Open(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer isoFile.Close()
	workDir := filepath.Join(root, "work")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareExtractedManifest(context.Background(), isoFile, isoMount, workDir, Options{
		Architecture: "arm64", RequireUEFI: true, RequireFAT32: true,
	}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Manifest.ElToritoOverlay == nil || prepared.Manifest.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" {
		prepared.Close()
		t.Fatalf("missing overlay evidence: %#v", prepared.Manifest)
	}
	if prepared.Manifest.ElToritoOverlay.PlanSHA256 == "" || prepared.Manifest.ElToritoOverlay.ImageSHA256 == "" {
		prepared.Close()
		t.Fatalf("incomplete overlay evidence: %#v", prepared.Manifest.ElToritoOverlay)
	}
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	if err := CopyAndVerify(context.Background(), prepared.Manifest, destination, CopyOptions{}); err != nil {
		prepared.Close()
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "EFI", "BOOT", "BOOTAA64.EFI")); err != nil || string(data) != string(linuxTestARM64EFI(0xa1)) {
		prepared.Close()
		t.Fatalf("overlay loader readback error=%v size=%d", err, len(data))
	}
	mountPath := prepared.overlayMount
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("findmnt", "-rn", "-T", mountPath, "-o", "TARGET").CombinedOutput()
	if err == nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("overlay mount survived cleanup: output=%q err=%v", output, err)
	}
}

func TestCreateExtractedOnRealLoopDeviceWithElToritoOverlay(t *testing.T) {
	if os.Getenv("RUFUS_REAL_EL_TORITO_OVERLAY_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EL_TORITO_OVERLAY_TEST=1 for privileged loop qualification")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real El Torito writer qualification requires root")
	}
	for _, name := range []string{"genisoimage", "mkfs.vfat", "mcopy", "mmd", "losetup", "blockdev", "mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "fsck.vfat", "blkid"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is unavailable: %v", name, err)
		}
	}
	root := t.TempDir()
	isoPath := buildRealElToritoISO(t, root, 0xa2)
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(root, "target.img")
	file, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(capacity); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	loopPath := attachExtractedLoop(t, backing)
	mountRoot := filepath.Join(root, "completed")
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
		t.Fatalf("unexpected target size %q: %v", sizeOutput, err)
	}
	workRoot := filepath.Join(root, "work")
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := CreateExtracted(context.Background(), resolvedISO, loopPath, ExtractedCreateOptions{
		TargetSize: targetSize, ExpectedDeviceID: deviceID, ExpectedSource: sourceIdentity,
		Architecture: "arm64", VolumeLabel: "ELTORITO", WorkDirectory: workRoot,
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
		t.Fatalf("create El Torito overlay media: %v; result=%+v", err, result)
	}
	if result.Manifest.ElToritoOverlay == nil || result.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" {
		t.Fatalf("missing El Torito result evidence: %+v", result)
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
	metadata, err := waitForExtractedBlkid(partitionPath, false, 10*time.Second)
	if err != nil || !strings.Contains(string(metadata), "TYPE=vfat") || !strings.Contains(string(metadata), "LABEL=ELTORITO") {
		t.Fatalf("unexpected completed metadata err=%v:\n%s", err, metadata)
	}
	output, err := waitForExtractedReadOnlyMount(partitionPath, mountRoot, "vfat", 10*time.Second)
	if err != nil {
		t.Fatalf("mount completed target: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = true
	loader, err := os.ReadFile(filepath.Join(mountRoot, "EFI", "BOOT", "BOOTAA64.EFI"))
	if err != nil || string(loader) != string(linuxTestARM64EFI(0xa2)) {
		t.Fatalf("fallback readback err=%v size=%d", err, len(loader))
	}
	kernel, err := os.ReadFile(filepath.Join(mountRoot, "casper", "vmlinuz"))
	if err != nil || string(kernel) != "kernel" {
		t.Fatalf("kernel readback=%q err=%v", kernel, err)
	}
	if output, err := exec.Command("umount", "--", mountRoot).CombinedOutput(); err != nil {
		t.Fatalf("unmount completed target: %v: %s", err, output)
	}
	mounted = false
}

func buildRealElToritoISO(t *testing.T, root string, marker byte) string {
	t.Helper()
	isoTree := filepath.Join(root, "iso-tree-writer")
	if err := os.MkdirAll(filepath.Join(isoTree, "casper"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isoTree, "casper", "vmlinuz"), []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(isoTree, "boot", "grub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isoTree, "boot", "grub", "grub.cfg"), []byte("linux /casper/vmlinuz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bootImage := filepath.Join(isoTree, "efi.img")
	file, err := os.OpenFile(bootImage, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(8 * 1024 * 1024); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runRealLinuxTest(t, "mkfs.vfat", "-F", "32", bootImage)
	runRealLinuxTest(t, "mmd", "-i", bootImage, "::/EFI", "::/EFI/BOOT")
	loader := filepath.Join(root, "BOOTAA64-writer.EFI")
	if err := os.WriteFile(loader, linuxTestARM64EFI(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	runRealLinuxTest(t, "mcopy", "-i", bootImage, loader, "::/EFI/BOOT/BOOTAA64.EFI")
	isoPath := filepath.Join(root, "eltorito-writer.iso")
	runRealLinuxTest(t, "genisoimage", "-quiet", "-R", "-J", "-V", "ELTORITO_WRITE", "-eltorito-alt-boot", "-e", "efi.img", "-no-emul-boot", "-o", isoPath, isoTree)
	return isoPath
}

func runRealLinuxTest(t *testing.T, name string, args ...string) {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, strings.TrimSpace(string(output)))
	}
}
