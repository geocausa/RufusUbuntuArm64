//go:build linux

package safety

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReopenableDeviceFlagsExcludeKernelExclusiveOpen(t *testing.T) {
	if reopenableDeviceOpenFlags&syscall.O_EXCL != 0 {
		t.Fatal("reopenable filesystem-tool descriptor must not use O_EXCL")
	}
}

func TestWithTemporarilyReleasedFlockRestoresLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked-device")
	if err := os.WriteFile(path, []byte("device"), 0o600); err != nil {
		t.Fatal(err)
	}
	primary, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	contender, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	if err := syscall.Flock(int(primary.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(primary.Fd()), syscall.LOCK_UN)
	if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)
		t.Fatal("contender unexpectedly acquired the initial lock")
	}
	run := false
	if err := WithTemporarilyReleasedFlock(primary, func() error {
		if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return fmt.Errorf("contender could not acquire released lock: %w", err)
		}
		run = true
		return syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)
	}); err != nil {
		t.Fatal(err)
	}
	if !run {
		t.Fatal("trusted operation did not run")
	}
	if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)
		t.Fatal("partition lock was not restored")
	}
}

func TestOpenReopenableDeviceRefusesSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "device")
	if err := os.WriteFile(target, []byte("device"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "device-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenReopenableDevice(link); err == nil {
		file.Close()
		t.Fatal("symbolic-link device path accepted")
	}
}

func TestOpenReopenableDeviceSupportsFilesystemToolsOnLoop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 and run as root for the loop-device regression")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real block-device regression requires root")
	}
	for _, program := range []string{"losetup", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck", "mount", "umount"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatalf("required integration-test program %q is unavailable: %v", program, err)
		}
	}

	imagePath := filepath.Join(t.TempDir(), "formatter-loop.img")
	image, err := os.OpenFile(imagePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := image.Truncate(256 * 1024 * 1024); err != nil {
		image.Close()
		t.Fatal(err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command("losetup", "--find", "--show", imagePath).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	if loopPath == "" {
		t.Fatal("losetup returned an empty loop-device path")
	}
	mountedAt := ""
	defer func() {
		if mountedAt != "" {
			_ = exec.Command("umount", "--", mountedAt).Run()
		}
		if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
			t.Errorf("detach loop device: %v: %s", err, strings.TrimSpace(string(output)))
		}
	}()

	device, err := OpenReopenableDevice(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if err := syscall.Flock(int(device.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("lock loop device: %v", err)
	}
	defer syscall.Flock(int(device.Fd()), syscall.LOCK_UN) // best effort

	// A loop device is deliberately not accepted by the production whole-disk
	// policy. This integration test is scoped to the formatter descriptor and
	// advisory-lock handoff only.
	const inheritedDevice = "/proc/self/fd/3"
	runInheritedDeviceCommandUnlocked(t, device, "mkfs.vfat", "-F", "32", inheritedDevice)
	runInheritedDeviceCommand(t, device, "fsck.vfat", "-n", inheritedDevice)

	mountDir := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(mountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runInheritedDeviceCommand(t, device, "mount", "-t", "vfat", "-o", "rw,nosuid,nodev,noexec", "--", inheritedDevice, mountDir)
	mountedAt = mountDir
	if err := os.WriteFile(filepath.Join(mountDir, "probe"), []byte("fat32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFormatterTestCommand(t, "umount", "--", mountDir)
	mountedAt = ""

	runInheritedDeviceCommandUnlocked(t, device, "mkfs.ext4", "-F", "-m", "0", inheritedDevice)
	runInheritedDeviceCommand(t, device, "mount", "-t", "ext4", "-o", "rw,nosuid,nodev,noexec", "--", inheritedDevice, mountDir)
	mountedAt = mountDir
	if err := os.WriteFile(filepath.Join(mountDir, "probe"), []byte("ext4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFormatterTestCommand(t, "umount", "--", mountDir)
	mountedAt = ""
	runInheritedDeviceCommand(t, device, "e2fsck", "-f", "-n", inheritedDevice)
}

func runInheritedDeviceCommandUnlocked(t *testing.T, device *os.File, name string, args ...string) {
	t.Helper()
	err := WithTemporarilyReleasedFlock(device, func() error {
		command := exec.Command(name, args...)
		command.ExtraFiles = []*os.File{device}
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("%s failed: %w: %s", formatCommand(name, args), runErr, strings.TrimSpace(string(output)))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func runInheritedDeviceCommand(t *testing.T, device *os.File, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.ExtraFiles = []*os.File{device}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", formatCommand(name, args), err, strings.TrimSpace(string(output)))
	}
}

func runFormatterTestCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", formatCommand(name, args), err, strings.TrimSpace(string(output)))
	}
}

func formatCommand(name string, args []string) string {
	return fmt.Sprintf("%s %s", name, strings.Join(args, " "))
}
