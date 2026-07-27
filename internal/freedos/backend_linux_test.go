//go:build linux

package freedos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

func TestExecuteLinuxDeviceRejectsUnboundOptions(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	noop := func(*os.File) error { return nil }
	tests := []struct {
		name    string
		options LinuxDeviceOptions
		want    string
	}{
		{
			name:    "missing identity",
			options: LinuxDeviceOptions{Revalidate: noop},
			want:    "bound kernel device identity",
		},
		{
			name:    "missing revalidation",
			options: LinuxDeviceOptions{ExpectedDeviceID: 1},
			want:    "live policy and identity callback",
		},
		{
			name: "size mismatch",
			options: LinuxDeviceOptions{
				ExpectedDeviceID: 1,
				ExpectedSize:     plan.DeviceSizeBytes + 512,
				Revalidate:       noop,
			},
			want: "size does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := ExecuteLinuxDevice(context.Background(), plan, test.options, ExecutionOptions{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want text %q", err, test.want)
			}
			if report.Schema != 0 || report.MediaChanged || report.BytesWritten != 0 || report.BytesVerified != 0 || report.Reusable {
				t.Fatalf("invalid backend options produced execution state: %+v", report)
			}
		})
	}
}

func TestExecuteLinuxDeviceThroughRealLoop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 and run as root for the destructive loop regression")
	}
	if os.Geteuid() != 0 {
		t.Fatal("destructive FreeDOS loop regression requires root")
	}
	for _, program := range []string{"losetup", "blockdev", "sync", "blkid", "fsck.vfat"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatalf("required integration-test program %q is unavailable: %v", program, err)
		}
	}

	backingPath := filepath.Join(t.TempDir(), "freedos-device.img")
	backing, err := os.OpenFile(backingPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := backing.Truncate(int64(testMediaSize)); err != nil {
		backing.Close()
		t.Fatal(err)
	}
	const untouchedOffset = int64(20 * 1024 * 1024)
	const untouchedValue = byte(0xa5)
	if _, err := backing.WriteAt([]byte{untouchedValue}, untouchedOffset); err != nil {
		backing.Close()
		t.Fatal(err)
	}
	if err := backing.Sync(); err != nil {
		backing.Close()
		t.Fatal(err)
	}
	if err := backing.Close(); err != nil {
		t.Fatal(err)
	}

	loopPath := attachFreeDOSLoop(t, backingPath, false)
	attached := true
	defer func() {
		if attached {
			detachFreeDOSLoop(t, loopPath)
		}
	}()

	kernelID, err := safety.KernelDeviceID(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildDevicePlan(DeviceRequest{
		DevicePath:        loopPath,
		ExpectedIdentity:  fmt.Sprintf("kernel-device:%d", kernelID),
		DeviceSizeBytes:   testMediaSize,
		LogicalSectorSize: 512,
		Label:             "FREEDOS",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.MutationBytes >= plan.DeviceSizeBytes || plan.UntouchedBytes == 0 {
		t.Fatalf("loop plan does not preserve free data: %+v", plan)
	}

	revalidations := 0
	report, err := ExecuteLinuxDevice(context.Background(), plan, LinuxDeviceOptions{
		ExpectedDeviceID: kernelID,
		ExpectedSize:     testMediaSize,
		Revalidate: func(file *os.File) error {
			revalidations++
			if err := safety.VerifyOpenDevice(file, kernelID, testMediaSize); err != nil {
				return err
			}
			currentID, err := safety.KernelDeviceID(loopPath)
			if err != nil {
				return err
			}
			if currentID != kernelID {
				return fmt.Errorf("loop path identity changed from %d to %d", kernelID, currentID)
			}
			return nil
		},
	}, ExecutionOptions{})
	if err != nil {
		t.Fatalf("execute FreeDOS loop backend: %v", err)
	}
	if report.Status != ExecutionStatusSucceeded || !report.MediaChanged || !report.Verified || !report.Reusable ||
		report.BytesWritten != plan.MutationBytes || report.BytesVerified != plan.VerificationBytes ||
		report.VerificationScope != MediaVerificationScope || report.SHA256 == "" {
		t.Fatalf("unexpected successful loop report: %+v", report)
	}
	if revalidations != 3 {
		t.Fatalf("live target revalidation ran %d times; want 3", revalidations)
	}

	detachFreeDOSLoop(t, loopPath)
	attached = false
	loopPath = attachFreeDOSLoop(t, backingPath, true)
	attached = true
	partitionPath := loopPath + "p1"
	if err := waitForFreeDOSLoopPartition(partitionPath, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	blkidFields := parseFreeDOSLoopExport(runFreeDOSLoopCommand(t, "blkid", "-p", "-o", "export", partitionPath))
	if blkidFields["TYPE"] != "vfat" || blkidFields["LABEL"] != plan.Label {
		t.Fatalf("written partition identified as TYPE=%q LABEL=%q; want vfat/%s", blkidFields["TYPE"], blkidFields["LABEL"], plan.Label)
	}
	runFreeDOSLoopCommand(t, "fsck.vfat", "-n", "-v", partitionPath)

	readback := readFreeDOSLoopBytes(t, loopPath, int(testMediaSize))
	if readback[untouchedOffset] != untouchedValue {
		t.Fatalf("unallocated data byte at %d changed from %#x to %#x", untouchedOffset, untouchedValue, readback[untouchedOffset])
	}
	if err := VerifyMediaImage(readback, plan.Media); err != nil {
		t.Fatalf("verify detached and reattached loop media: %v", err)
	}
}

func attachFreeDOSLoop(t *testing.T, backingPath string, readOnly bool) string {
	t.Helper()
	args := []string{"--find", "--show", "--partscan"}
	if readOnly {
		args = append(args, "--read-only")
	}
	args = append(args, "--", backingPath)
	output, err := exec.Command("losetup", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("attach FreeDOS loop: %v: %s", err, strings.TrimSpace(string(output)))
	}
	path := strings.TrimSpace(string(output))
	if path == "" {
		t.Fatal("losetup returned an empty loop-device path")
	}
	return path
}

func detachFreeDOSLoop(t *testing.T, path string) {
	t.Helper()
	output, err := exec.Command("losetup", "--detach", path).CombinedOutput()
	if err != nil {
		t.Fatalf("detach FreeDOS loop %s: %v: %s", path, err, strings.TrimSpace(string(output)))
	}
}
