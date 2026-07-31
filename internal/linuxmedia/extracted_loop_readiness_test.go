//go:build linux

package linuxmedia

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// waitForExtractedBlkid waits for the independently reattached partition node
// to become readable by blkid. Geometry can appear before the kernel has made
// the replacement partition node fully usable, especially under repeated loop
// qualification. The final metadata checks remain the authority.
func waitForExtractedBlkid(partitionPath string, noEncoding bool, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var lastOutput []byte
	var lastErr error
	for time.Now().Before(deadline) {
		args := []string{"-p"}
		if noEncoding {
			args = append(args, "--no-encoding")
		}
		args = append(args, "-o", "export", partitionPath)
		lastOutput, lastErr = exec.Command("blkid", args...).CombinedOutput()
		if lastErr == nil && len(strings.TrimSpace(string(lastOutput))) != 0 {
			return lastOutput, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("blkid did not recognize %s before timeout: %v: %s", partitionPath, lastErr, strings.TrimSpace(string(lastOutput)))
}

// waitForExtractedReadOnlyMount waits only for the reattached block node to
// become mountable. It never changes the filesystem and retains the exact
// read-only/no-device-execution options used by the independent qualification.
func waitForExtractedReadOnlyMount(partitionPath, mountRoot, filesystem string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var lastOutput []byte
	var lastErr error
	for time.Now().Before(deadline) {
		args := make([]string, 0, 8)
		if filesystem != "" {
			args = append(args, "-t", filesystem)
		}
		args = append(args, "-o", "ro,nosuid,nodev,noexec", "--", partitionPath, mountRoot)
		lastOutput, lastErr = exec.Command("mount", args...).CombinedOutput()
		if lastErr == nil {
			return lastOutput, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("completed %s partition did not become read-only mountable within %s: %v: %s", filesystem, timeout, lastErr, strings.TrimSpace(string(lastOutput)))
}
