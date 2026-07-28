//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

type cancelAfterPartitionBackend struct {
	*linuxBackend
	cancel context.CancelFunc
}

func (backend *cancelAfterPartitionBackend) Partition(ctx context.Context, plan Plan, table PartitionTable, script string) (string, error) {
	path, err := backend.linuxBackend.Partition(ctx, plan, table, script)
	if err == nil {
		backend.cancel()
	}
	return path, err
}

func TestExecuteDeviceInterruptionAfterPartitionOnRealLoop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise real loop devices")
	}
	if os.Geteuid() != 0 {
		t.Skip("real formatter loop tests require root")
	}
	for _, tool := range []string{"losetup", "blockdev", "sfdisk", "wipefs", "blkid", "mkfs.vfat", "fsck.vfat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required loop-test tool %q is unavailable: %v", tool, err)
		}
	}
	const capacity = 256 * 1024 * 1024
	backing := filepath.Join(t.TempDir(), "interrupted.img")
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
	output, err := exec.Command("losetup", "--find", "--show", "--partscan", backing).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	t.Cleanup(func() { _, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput() })
	waitForFormatterLoopLock(t, loopPath)
	deviceID, err := safety.KernelDeviceID(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	sectorOutput, err := exec.Command("blockdev", "--getss", loopPath).CombinedOutput()
	if err != nil {
		t.Fatalf("read logical sector size: %v: %s", err, strings.TrimSpace(string(sectorOutput)))
	}
	sectorSize, err := strconv.ParseUint(strings.TrimSpace(string(sectorOutput)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(Request{
		DevicePath:        loopPath,
		ExpectedIdentity:  strings.Repeat("b", 64),
		DeviceSizeBytes:   capacity,
		LogicalSectorSize: sectorSize,
		Scheme:            SchemeGPT,
		Filesystem:        FilesystemFAT32,
		Label:             "INTERRUPT",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	backend := &linuxBackend{options: DeviceOptions{
		ExpectedDeviceID: deviceID,
		ExpectedSize:     capacity,
		PartitionTimeout: 30 * time.Second,
		BeforeDestructive: func(open *os.File) error {
			return safety.VerifyOpenDevice(open, deviceID, capacity)
		},
	}}
	wrapper := &cancelAfterPartitionBackend{linuxBackend: backend, cancel: cancel}
	report, runErr := Execute(ctx, plan, wrapper, time.Now)
	report, runErr = finishDeviceExecution(report, runErr, backend.Close(), time.Now)
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation; report=%+v", runErr, report)
	}
	if report.Status != StatusCancelled || !report.MediaChanged || report.Reusable || report.Filesystem != nil || report.Failure == nil || report.Failure.Phase != PhaseFormat {
		t.Fatalf("unsafe post-partition cancellation report: %+v", report)
	}
	if backend.partitionPath == "" {
		t.Fatal("real loop interruption did not publish a partition node")
	}
	filesystem, _ := exec.Command("blkid", "-o", "value", "-s", "TYPE", backend.partitionPath).CombinedOutput()
	if strings.TrimSpace(string(filesystem)) != "" {
		t.Fatalf("post-partition cancellation unexpectedly created a filesystem: %q", strings.TrimSpace(string(filesystem)))
	}
}
