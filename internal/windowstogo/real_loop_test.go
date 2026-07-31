//go:build linux

package windowstogo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreateRealWindowsARM64Loop(t *testing.T) {
	if os.Getenv("RUFUS_REAL_WINDOWS_TO_GO_TEST") != "1" {
		t.Skip("set RUFUS_REAL_WINDOWS_TO_GO_TEST=1 for the privileged real-ISO loop transaction")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real Windows To Go loop test must run as root")
	}
	isoPath := os.Getenv("RUFUS_WINDOWS_ARM64_ISO")
	wimPath := os.Getenv("RUFUS_WIMLIB_IMAGE_X")
	if isoPath == "" || wimPath == "" {
		t.Fatal("RUFUS_WINDOWS_ARM64_ISO and RUFUS_WIMLIB_IMAGE_X are required")
	}
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	wimExecutableOverride = filepath.Clean(wimPath)
	defer func() { wimExecutableOverride = "" }()

	workDir, err := os.MkdirTemp("/var/tmp", "rufusarm64-wtg-loop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(workDir)
	diskImage := filepath.Join(workDir, "windows-to-go.img")
	file, err := os.OpenFile(diskImage, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(32 * 1024 * 1024 * 1024)
	if err := file.Truncate(int64(targetSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	loopOutput, err := exec.Command("losetup", "--find", "--show", "--partscan", "--sector-size", "512", diskImage).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop: %v: %s", err, loopOutput)
	}
	loopPath := strings.TrimSpace(string(loopOutput))
	defer func() {
		_ = exec.Command("umount", partitionDevicePath(loopPath, 1)).Run()
		_ = exec.Command("umount", partitionDevicePath(loopPath, 2)).Run()
		if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
			t.Errorf("detach loop: %v: %s", err, output)
		}
	}()
	info, err := os.Stat(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Rdev == 0 {
		t.Fatal("loop target has no block-device identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	var events []Event
	result, err := Create(ctx, resolvedISO, loopPath, CreateOptions{
		TargetSizeBytes: targetSize, LogicalSectorSize: 512,
		ExpectedDeviceID: uint64(stat.Rdev), ExpectedIdentity: "real-loop-windows-to-go",
		ExpectedSource: sourceIdentity, ImageIndex: 3,
	}, func(event Event) {
		events = append(events, event)
		t.Logf("%s: %s (%d/%d)", event.Stage, event.Message, event.Done, event.Total)
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if result.Plan.Image.Index != 3 || result.Plan.Architecture != "arm64" || result.Plan.BootableClaim || result.FirmwareBootVerified {
		t.Fatalf("result escaped experimental boundary: %#v", result)
	}
	if result.Materialization.BootFiles == 0 || result.Materialization.BCD.OutputBytes == 0 ||
		result.Materialization.BootManagerSHA256 == "" || result.Materialization.OfflinePolicySHA256 == "" {
		t.Fatalf("incomplete materialization evidence: %#v", result.Materialization)
	}
	var sawApplyProgress, sawApplyComplete bool
	for _, event := range events {
		if event.Stage != "apply" || event.Total != result.Plan.Image.TotalBytes {
			continue
		}
		if event.Done > 0 && event.Done < event.Total {
			sawApplyProgress = true
		}
		if event.Done == event.Total {
			sawApplyComplete = true
		}
	}
	if !sawApplyProgress || !sawApplyComplete {
		t.Fatalf("live WIM apply progress was not complete: progress=%v complete=%v events=%#v", sawApplyProgress, sawApplyComplete, events)
	}
	if len(events) == 0 || events[len(events)-1].Stage != "complete" {
		t.Fatalf("completion event missing: %#v", events)
	}
}
