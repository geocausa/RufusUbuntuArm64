//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestFinishWindowsMediaFileCleanlyUnlocksAndCloses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "windows-media-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := finishWindowsMediaFile(nil, file, true, "test target"); err != nil {
		t.Fatalf("clean finalization failed: %v", err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("descriptor remained open after finalization")
	}
}

func TestFinishWindowsMediaFileReportsUnlockAndCloseFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "windows-media-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishWindowsMediaFile(nil, file, true, "test target")
	if err == nil {
		t.Fatal("finalization failure was ignored")
	}
	if !strings.Contains(err.Error(), "unlock test target") || !strings.Contains(err.Error(), "close test target") {
		t.Fatalf("finalization errors were not preserved: %v", err)
	}
}

func TestFinishWindowsMediaFilePreservesPriorCancellation(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "windows-media-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishWindowsMediaFile(context.Canceled, file, true, "test target")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "unlock test target") || !strings.Contains(err.Error(), "close test target") {
		t.Fatalf("finalization errors were not joined: %v", err)
	}
}
