//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestFullFlashTargetPreflightProductionSourceIsReadOnly(t *testing.T) {
	data, err := os.ReadFile("restore_target_preflight_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"ResolveAuthenticatedSingleStoreV1FullFlash",
		"device.Find",
		"safety.ValidateExpectedIdentity",
		"safety.ValidateTarget(resolved, dev, false)",
		"safety.KernelDeviceID",
		"logical_block_size",
		"physical_block_size",
		"RunningSystemDiskExcluded:      true",
		"FixedDiskOverrideAllowed:       false",
		"PrivilegedOpenRequired:         true",
		"ExecutionSupported:             false",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU target-preflight source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.WriteFile(",
		"WriteAt(",
		"unix.Open(",
		"syscall.Open(",
		"syscall.Flock(",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"ExecutionSupported:             true",
		"FixedDiskOverrideAllowed:       true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU target-preflight source contains forbidden mutation or privilege primitive %q", forbidden)
		}
	}
}
