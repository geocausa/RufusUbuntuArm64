//go:build linux

package safety

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/device"
)

func TestValidateTargetMetadata(t *testing.T) {
	valid := device.BlockDevice{Path: "/dev/sda", Type: "disk", Size: 1024, Transport: "usb"}
	if err := ValidateTargetMetadata("/dev/sda", valid, false); err != nil {
		t.Fatalf("valid USB rejected: %v", err)
	}
	partition := valid
	partition.Type = "part"
	if err := ValidateTargetMetadata("/dev/sda", partition, false); err == nil {
		t.Fatal("partition accepted")
	}
	internalMMC := valid
	internalMMC.Transport = "mmc"
	if err := ValidateTargetMetadata("/dev/sda", internalMMC, false); err == nil {
		t.Fatal("internal MMC accepted without override")
	}
}

func TestValidateExpectedIdentity(t *testing.T) {
	dev := device.BlockDevice{Path: "/dev/sda", Type: "disk", Size: 1024, MajorMinor: "8:0", Transport: "usb"}
	expected := device.IdentityToken(dev)
	if err := ValidateExpectedIdentity(dev, expected); err != nil {
		t.Fatal(err)
	}
	dev.MajorMinor = "8:16"
	if err := ValidateExpectedIdentity(dev, expected); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("identity change not rejected: %v", err)
	}
}

func TestMountDepth(t *testing.T) {
	if mountDepth("/media") >= mountDepth("/media/usb/sub") {
		t.Fatal("nested mount was not considered deeper")
	}
}

func TestBackingDisksForPathHandlesBtrfsSubvolumeAndStack(t *testing.T) {
	fakeBin := t.TempDir()
	writeFake(t, filepath.Join(fakeBin, "findmnt"), "#!/bin/sh\nprintf '/dev/mapper/cryptroot[/@]\\n'\n")
	writeFake(t, filepath.Join(fakeBin, "lsblk"), "#!/bin/sh\nprintf 'cryptroot crypt\\nnvme0n1p3 part\\nnvme0n1 disk\\n'\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	disks, err := BackingDisksForPath("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(disks) != 1 || disks[0] != "nvme0n1" {
		t.Fatalf("unexpected disks: %v", disks)
	}
}

func TestUnmountDescendantsUsesDeepestMountFirst(t *testing.T) {
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "umount.log")
	t.Setenv("RUFUS_TEST_LOG", logPath)
	writeFake(t, filepath.Join(fakeBin, "umount"), "#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$RUFUS_TEST_LOG\"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dev := device.BlockDevice{Path: "/dev/sda", Type: "disk", Children: []device.BlockDevice{
		{Path: "/dev/sda1", Type: "part", Mountpoints: []string{"/media/usb", "/media/usb/nested"}},
	}}
	if err := UnmountDescendants(dev); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] != "/media/usb/nested" || lines[1] != "/media/usb" {
		t.Fatalf("unexpected unmount order: %q", data)
	}
}

func TestEnsureNoMountedDescendantsFailsClosed(t *testing.T) {
	fakeBin := t.TempDir()
	jsonOutput := `{"blockdevices":[{"name":"sda","path":"/dev/sda","type":"disk","size":1000,"model":"","vendor":"","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"","wwn":"","children":[{"name":"sda1","path":"/dev/sda1","type":"part","size":900,"model":"","vendor":"","tran":"","rm":0,"ro":0,"hotplug":0,"mountpoints":["/media/usb"],"pkname":"sda","maj:min":"8:1","serial":"","wwn":""}]}]}`
	writeFake(t, filepath.Join(fakeBin, "lsblk"), "#!/bin/sh\nprintf '%s\\n' '"+jsonOutput+"'\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := EnsureNoMountedDescendants("/dev/sda"); err == nil || !strings.Contains(err.Error(), "mounted again") {
		t.Fatalf("expected mounted-target refusal, got %v", err)
	}
}

func writeFake(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTargetMetadataRejectsProtectedMounts(t *testing.T) {
	dev := device.BlockDevice{
		Path:      "/dev/sda",
		Type:      "disk",
		Size:      1024,
		Transport: "usb",
		Children: []device.BlockDevice{{
			Path:        "/dev/sda1",
			Type:        "part",
			Mountpoints: []string{"/boot/efi"},
		}},
	}
	if err := ValidateTargetMetadata(dev.Path, dev, false); err == nil {
		t.Fatal("system boot mount was accepted")
	}
	dev.Children[0].Mountpoints = []string{"/media/user/USB"}
	if err := ValidateTargetMetadata(dev.Path, dev, false); err != nil {
		t.Fatalf("normal desktop USB mount was rejected: %v", err)
	}
	dev.Children[0].Mountpoints = []string{"/mnt/temporary-usb"}
	if err := ValidateTargetMetadata(dev.Path, dev, false); err != nil {
		t.Fatalf("explicit temporary mount was rejected: %v", err)
	}
	dev.Children[0].Mountpoints = []string{"/srv/important-data"}
	if err := ValidateTargetMetadata(dev.Path, dev, false); err == nil {
		t.Fatal("non-removable-media data mount was accepted")
	}
	dev.Children[0].Mountpoints = []string{"[SWAP]"}
	if err := ValidateTargetMetadata(dev.Path, dev, false); err == nil {
		t.Fatal("active swap device was accepted")
	}
}

func TestCancellationContextRejectsUntrustedUse(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	if _, _, err := CancellationContext(context.Background(), "/run/user/1000/rufusarm64-test.cancel"); err == nil {
		t.Fatal("cancel file accepted outside pkexec")
	}
	t.Setenv("PKEXEC_UID", "1000")
	if _, _, err := CancellationContext(context.Background(), "/tmp/rufusarm64-test.cancel"); err == nil {
		t.Fatal("cancel file outside runtime directory was accepted")
	}
}
