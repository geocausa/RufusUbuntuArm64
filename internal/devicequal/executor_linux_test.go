//go:build linux

package devicequal

import (
	"context"
	"errors"
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

func TestRunDeviceRejectsMissingBindingBeforeOpen(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		options DeviceOptions
	}{
		{name: "nil context", path: "/does/not/exist", options: DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1}},
		{name: "empty path", path: "", options: DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1}},
		{name: "missing identity", path: "/does/not/exist", options: DeviceOptions{ExpectedSize: 1}},
		{name: "missing capacity", path: "/does/not/exist", options: DeviceOptions{ExpectedDeviceID: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.name == "nil context" {
				ctx = nil
			}
			if _, err := RunDevice(ctx, test.path, test.options); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRunDeviceHonorsCancelledContextBeforeOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunDevice(ctx, "/does/not/exist", DeviceOptions{ExpectedDeviceID: 1, ExpectedSize: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestAcquireExclusiveFlockWaitsForTransientHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qualification-lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Flock(int(first.Fd()), syscall.LOCK_UN)
		close(released)
	}()
	if err := acquireExclusiveFlock(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(second.Fd()), syscall.LOCK_UN)
	<-released
}

func TestAcquireExclusiveFlockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qualification-lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(first.Fd()), syscall.LOCK_UN)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acquireExclusiveFlock(ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestRunDeviceQualifiesRealLoopDevice(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real loop-device qualification requires root")
	}
	if _, err := exec.LookPath("losetup"); err != nil {
		t.Skip("losetup is unavailable")
	}
	if _, err := exec.LookPath("blockdev"); err != nil {
		t.Skip("blockdev is unavailable")
	}

	const size = 256 * 1024
	backing := filepath.Join(t.TempDir(), "qualification-loop.img")
	file, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command("losetup", "--find", "--show", "--", backing).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
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

	beforeCalls := 0
	report, err := RunDevice(context.Background(), loopPath, DeviceOptions{
		ExpectedDeviceID: deviceID,
		ExpectedSize:     capacity,
		Profile:          ProfileFull,
		RegionSize:       64 * 1024,
		BufferSize:       4096,
		Patterns:         []Pattern{{ID: "loop-address", Seed: 0x12345678}},
		BeforeWrite: func(open *os.File) error {
			beforeCalls++
			return safety.VerifyOpenDevice(open, deviceID, capacity)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if beforeCalls != 1 {
		t.Fatalf("before-write calls = %d, want 1", beforeCalls)
	}
	if report.Status != StatusPassed || report.CompletedBytes != 2*capacity {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Passes) != 1 || report.Passes[0].WrittenBytes != capacity || report.Passes[0].VerifiedBytes != capacity {
		t.Fatalf("unexpected pass report: %+v", report.Passes)
	}
}
