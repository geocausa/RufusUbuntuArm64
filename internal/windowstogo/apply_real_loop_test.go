//go:build linux

package windowstogo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunWIMApplyRealNTFSLoop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_WIM_PROGRESS_TEST") != "1" {
		t.Skip("set RUFUS_REAL_WIM_PROGRESS_TEST=1 for the privileged direct-NTFS progress transaction")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real direct-NTFS progress test must run as root")
	}
	wimlib := os.Getenv("RUFUS_WIMLIB_IMAGE_X")
	if wimlib == "" {
		wimlib = bundledWIMExecutable
	}
	for _, tool := range []string{"losetup", "mkntfs", "ntfsfix", "mount", "umount"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}

	workDir, err := os.MkdirTemp("/var/tmp", "rufusarm64-wim-progress-loop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(workDir)
	sourceDir := filepath.Join(workDir, "source")
	mountDir := filepath.Join(workDir, "mount")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const fileCount = 6
	const fileSize = 8 * 1024 * 1024
	var sourceBytes uint64
	for index := 0; index < fileCount; index++ {
		path := filepath.Join(sourceDir, fmt.Sprintf("payload-%d.bin", index))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(file, rand.Reader, fileSize); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		sourceBytes += fileSize
	}
	wimPath := filepath.Join(workDir, "test.wim")
	if output, err := exec.Command(wimlib, "capture", sourceDir, wimPath, "Progress Test", "--compress=none").CombinedOutput(); err != nil {
		t.Fatalf("capture fixture WIM: %v: %s", err, output)
	}

	imagePath := filepath.Join(workDir, "target.img")
	image, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
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
		t.Fatalf("attach loop: %v: %s", err, output)
	}
	loopPath := strings.TrimSpace(string(output))
	defer func() {
		_ = exec.Command("umount", mountDir).Run()
		if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
			t.Errorf("detach loop: %v: %s", err, output)
		}
	}()
	if output, err := exec.Command("mkntfs", "-F", "-Q", "-L", "WTG_PROGRESS", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("format loop NTFS: %v: %s", err, output)
	}
	info, err := os.Stat(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Rdev == 0 {
		t.Fatal("loop target has no block-device identity")
	}
	health, err := newTargetHealthMonitor(loopPath, uint64(stat.Rdev))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var events []Event
	if err := runWIMApply(
		ctx, wimlib, []string{"apply", wimPath, "1", loopPath}, "Applying test image…",
		sourceBytes, health, 20*time.Millisecond, func(event Event) { events = append(events, event) },
	); err != nil {
		t.Fatal(err)
	}
	var intermediate, complete bool
	for _, event := range events {
		if event.Stage != "apply" || event.Total != sourceBytes {
			continue
		}
		if event.Done > 0 && event.Done < event.Total {
			intermediate = true
		}
		if event.Done == event.Total {
			complete = true
		}
	}
	if !intermediate || !complete {
		t.Fatalf("incomplete progress events: %#v", events)
	}
	if output, err := exec.Command("ntfsfix", "-n", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("check applied NTFS volume: %v: %s", err, output)
	}
	if output, err := exec.Command("mount", "-o", "ro,norecover", loopPath, mountDir).CombinedOutput(); err != nil {
		t.Fatalf("mount applied NTFS volume: %v: %s", err, output)
	}
	for index := 0; index < fileCount; index++ {
		name := fmt.Sprintf("payload-%d.bin", index)
		sourceDigest, err := fileSHA256(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		targetDigest, err := fileSHA256(filepath.Join(mountDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if sourceDigest != targetDigest {
			t.Fatalf("content mismatch for %s", name)
		}
	}
	if output, err := exec.Command("umount", mountDir).CombinedOutput(); err != nil {
		t.Fatalf("unmount applied NTFS volume: %v: %s", err, output)
	}
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
