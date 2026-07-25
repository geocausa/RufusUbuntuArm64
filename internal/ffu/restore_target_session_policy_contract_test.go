//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestExclusiveTargetSessionProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("restore_target_session_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"os.O_RDWR|syscall.O_EXCL|syscall.O_NOFOLLOW",
		"safety.VerifyOpenDevice",
		"safety.RevalidateOpenBoundTarget(path, expectedKernelID, false)",
		"safety.EnsureOpenFileNotOnTarget",
		"sourceLease.lease.Check()",
		"sourcefile.Verify",
		"issuedFullFlashTargetSessionSeal",
		"MountedTargetsAbsent:           true",
		"GuardedUnmountPerformed:        false",
		"FixedDiskOverrideAllowed:       false",
		"TargetAccessAcquired:           true",
		"MutationPermitted:              false",
		"ExecutionSupported:             false",
		"exposes no descriptor, read, write, seek, sync, or ioctl method",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("exclusive FFU target-session source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"func (session *FullFlashTargetSession) File(",
		"func (session *FullFlashTargetSession) Read(",
		"func (session *FullFlashTargetSession) ReadAt(",
		"func (session *FullFlashTargetSession) Write(",
		"func (session *FullFlashTargetSession) WriteAt(",
		"func (session *FullFlashTargetSession) Seek(",
		"func (session *FullFlashTargetSession) Sync(",
		"func (session *FullFlashTargetSession) Fd(",
		"syscall.Flock(",
		"Unmount(",
		"umount",
		"pkexec",
		"polkit",
		"FixedDiskOverrideAllowed:       true",
		"MutationPermitted:              true",
		"ExecutionSupported:             true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("exclusive FFU target-session source contains forbidden exposure or mutation primitive %q", forbidden)
		}
	}
}
