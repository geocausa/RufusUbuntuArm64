//go:build linux

package freedos

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildMediaImageSupportsRealLoopReadback(t *testing.T) {
	if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
		t.Skip("set RUFUS_REAL_BLOCK_TEST=1 and run as root for the loop-device regression")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real block-device regression requires root")
	}
	for _, program := range []string{"losetup", "blockdev", "lsblk", "blkid", "fsck.vfat"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatalf("required integration-test program %q is unavailable: %v", program, err)
		}
	}

	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	image, err := BuildMediaImage(plan)
	if err != nil {
		t.Fatalf("build FreeDOS media: %v", err)
	}
	imagePath := filepath.Join(t.TempDir(), "freedos-loop.img")
	if err := os.WriteFile(imagePath, image, 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command("losetup", "--find", "--show", "--partscan", "--read-only", "--", imagePath).CombinedOutput()
	if err != nil {
		t.Fatalf("attach read-only loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	if loopPath == "" {
		t.Fatal("losetup returned an empty loop-device path")
	}
	deferredDetach := true
	defer func() {
		if deferredDetach {
			if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
				t.Errorf("detach loop device: %v: %s", err, strings.TrimSpace(string(output)))
			}
		}
	}()

	partitionPath := loopPath + "p1"
	if err := waitForFreeDOSLoopPartition(partitionPath, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if got := runFreeDOSLoopCommand(t, "blockdev", "--getss", loopPath); got != strconv.Itoa(int(plan.LogicalSectorSize)) {
		t.Fatalf("loop logical sector size = %q; want %d", got, plan.LogicalSectorSize)
	}
	if got := runFreeDOSLoopCommand(t, "blockdev", "--getsize64", loopPath); got != strconv.FormatUint(plan.DiskSizeBytes, 10) {
		t.Fatalf("loop size = %q; want %d", got, plan.DiskSizeBytes)
	}

	partitionFields := strings.Fields(runFreeDOSLoopCommand(t, "lsblk", "-b", "-n", "-o", "START,SIZE,TYPE", partitionPath))
	if len(partitionFields) != 3 {
		t.Fatalf("unexpected lsblk partition output: %q", strings.Join(partitionFields, " "))
	}
	wantPartitionBytes := uint64(plan.PartitionSectorCount) * uint64(plan.LogicalSectorSize)
	if partitionFields[0] != strconv.FormatUint(uint64(plan.PartitionStartSector), 10) ||
		partitionFields[1] != strconv.FormatUint(wantPartitionBytes, 10) || partitionFields[2] != "part" {
		t.Fatalf("kernel partition geometry = %q; want start %d size %d type part", strings.Join(partitionFields, " "), plan.PartitionStartSector, wantPartitionBytes)
	}

	blkid := runFreeDOSLoopCommand(t, "blkid", "-p", "-o", "export", partitionPath)
	blkidFields := parseFreeDOSLoopExport(blkid)
	if blkidFields["TYPE"] != "vfat" || blkidFields["LABEL"] != plan.Label {
		t.Fatalf("blkid identified TYPE=%q LABEL=%q; want vfat/%s", blkidFields["TYPE"], blkidFields["LABEL"], plan.Label)
	}
	runFreeDOSLoopCommand(t, "fsck.vfat", "-n", "-v", partitionPath)

	wholeReadback := readFreeDOSLoopBytes(t, loopPath, len(image))
	if !bytes.Equal(wholeReadback, image) {
		t.Fatal("whole-device loop readback differs from the constructed image")
	}
	if err := VerifyMediaImage(wholeReadback, plan); err != nil {
		t.Fatalf("verify whole-device loop readback: %v", err)
	}

	partitionStart := int(plan.PartitionStartSector) * int(plan.LogicalSectorSize)
	partitionEnd := partitionStart + int(wantPartitionBytes)
	partitionReadback := readFreeDOSLoopBytes(t, partitionPath, int(wantPartitionBytes))
	if !bytes.Equal(partitionReadback, image[partitionStart:partitionEnd]) {
		t.Fatal("kernel partition readback differs from the reviewed partition bytes")
	}

	if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("detach loop device: %v: %s", err, strings.TrimSpace(string(output)))
	}
	deferredDetach = false
}

func waitForFreeDOSLoopPartition(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil {
			if info.Mode()&os.ModeDevice == 0 {
				return fmt.Errorf("loop partition path %s is not a device", path)
			}
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("kernel did not expose loop partition %s within %s", path, timeout)
}

func runFreeDOSLoopCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func readFreeDOSLoopBytes(t *testing.T, path string, size int) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := make([]byte, size)
	if _, err := io.ReadFull(file, result); err != nil {
		t.Fatalf("read %d bytes from %s: %v", size, path, err)
	}
	return result
}

func parseFreeDOSLoopExport(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			result[key] = value
		}
	}
	return result
}
