//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

func TestCaptureDeviceRejectsInvalidBindingBeforeOpen(t *testing.T) {
	absoluteOutput := filepath.Join(t.TempDir(), "drive.img")
	for _, test := range []struct {
		name    string
		ctx     context.Context
		source  string
		output  string
		options DeviceOptions
	}{
		{name: "nil context", source: "/does/not/exist", output: absoluteOutput, options: DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1}},
		{name: "empty source", ctx: context.Background(), output: absoluteOutput, options: DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1}},
		{name: "missing identity", ctx: context.Background(), source: "/does/not/exist", output: absoluteOutput, options: DeviceOptions{ExpectedSize: 1}},
		{name: "missing capacity", ctx: context.Background(), source: "/does/not/exist", output: absoluteOutput, options: DeviceOptions{ExpectedDeviceID: 1}},
		{name: "relative output", ctx: context.Background(), source: "/does/not/exist", output: "drive.img", options: DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := CaptureDevice(test.ctx, test.source, test.output, test.options)
			if err == nil || report.Status != StatusFailed || report.Failure == nil {
				t.Fatalf("unexpected validation result: report=%+v err=%v", report, err)
			}
		})
	}
}

func TestCaptureDeviceHonorsCancelledContextBeforePreflight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := CaptureDevice(ctx, "/does/not/exist", filepath.Join(t.TempDir(), "drive.img"), DeviceOptions{
		ExpectedDeviceID: 1,
		ExpectedSize:     1,
	})
	if !errors.Is(err, context.Canceled) || report.Status != StatusCancelled {
		t.Fatalf("unexpected cancellation: report=%+v err=%v", report, err)
	}
}

func TestCaptureDeviceRefusesExistingDestinationBeforeSourceOpen(t *testing.T) {
	output := filepath.Join(t.TempDir(), "existing.img")
	original := []byte("preserve existing destination")
	if err := os.WriteFile(output, original, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := CaptureDevice(context.Background(), "/does/not/exist", output, DeviceOptions{
		ExpectedDeviceID: 1,
		ExpectedSize:     1,
	})
	if err == nil || report.Failure == nil || report.Failure.Kind != "destination_preflight" {
		t.Fatalf("unexpected result: report=%+v err=%v", report, err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing destination changed: %q", got)
	}
}

func TestCaptureDeviceRefusesSymlinkDestinationDirectory(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	report, err := CaptureDevice(context.Background(), "/does/not/exist", filepath.Join(link, "drive.img"), DeviceOptions{
		ExpectedDeviceID: 1,
		ExpectedSize:     1,
	})
	if err == nil || report.Failure == nil || report.Failure.Kind != "destination_preflight" {
		t.Fatalf("unexpected result: report=%+v err=%v", report, err)
	}
}

func TestEnsureFreeSpaceRejectsImpossibleRequest(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := ensureFreeSpace(directory, math.MaxUint64); err == nil {
		t.Fatal("impossible free-space request was accepted")
	}
}

func TestPublishNoReplaceIsAtomicAndPreservesExistingFiles(t *testing.T) {
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	const temporaryName = ".partial"
	const outputName = "drive.img"
	temporary := filepath.Join(path, temporaryName)
	output := filepath.Join(path, outputName)
	if err := os.WriteFile(temporary, []byte("captured"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNoReplace(directory, temporaryName, outputName); err == nil {
		t.Fatal("publication replaced an existing destination")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing destination changed: %q", got)
	}
	if _, err := os.Stat(temporary); err != nil {
		t.Fatalf("temporary file was lost after refused publication: %v", err)
	}

	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := publishNoReplace(directory, temporaryName, outputName); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "captured" {
		t.Fatalf("published data = %q", got)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary name remains after publication: %v", err)
	}
}

func TestCaptureDeviceCapturesRealReadOnlyLoopDevice(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real loop-device backup requires root")
	}
	if _, err := exec.LookPath("losetup"); err != nil {
		t.Skip("losetup is unavailable")
	}
	if _, err := exec.LookPath("blockdev"); err != nil {
		t.Skip("blockdev is unavailable")
	}

	const size = 256 * 1024
	data := bytes.Repeat([]byte("rufusarm64-drive-backup\n"), size/len("rufusarm64-drive-backup\n"))
	if len(data) < size {
		data = append(data, bytes.Repeat([]byte{0x5a}, size-len(data))...)
	}
	backing := filepath.Join(t.TempDir(), "source-loop.img")
	if err := os.WriteFile(backing, data, 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("losetup", "--find", "--show", "--read-only", backing)
	output, err := command.CombinedOutput()
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

	destinationDir := t.TempDir()
	destination := filepath.Join(destinationDir, "captured.img")
	beforeCalls := 0
	report, err := CaptureDevice(context.Background(), loopPath, destination, DeviceOptions{
		ExpectedDeviceID: deviceID,
		ExpectedSize:     capacity,
		BufferSize:       4096,
		BeforeRead: func(open *os.File) error {
			beforeCalls++
			return safety.VerifyOpenDevice(open, deviceID, capacity)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if beforeCalls != 1 {
		t.Fatalf("before-read calls = %d, want 1", beforeCalls)
	}
	if report.Status != StatusPassed || report.CompletedBytes != capacity {
		t.Fatalf("unexpected report: %+v", report)
	}
	expectedHash := sha256.Sum256(data)
	if report.SHA256 != hex.EncodeToString(expectedHash[:]) {
		t.Fatalf("sha256 = %q, want %x", report.SHA256, expectedHash)
	}
	captured, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(captured, data) {
		t.Fatal("captured image differs from loop source")
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("destination mode = %o, want 600", info.Mode().Perm())
	}
	partials, err := filepath.Glob(filepath.Join(destinationDir, ".captured.img.rufusarm64-partial-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 0 {
		t.Fatalf("temporary outputs remain: %v", partials)
	}
}

func waitForReadOnlyLoopExclusive(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
		if err == nil {
			_ = file.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("loop device %s did not become exclusively readable: %v", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
