package imaging

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestFinishWriteTargetCleanlyUnlocksAndCloses(t *testing.T) {
	target, err := os.CreateTemp(t.TempDir(), "target-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := finishWriteTarget(nil, target, true); err != nil {
		t.Fatalf("clean target cleanup failed: %v", err)
	}
	if _, err := target.Stat(); err == nil {
		t.Fatal("target descriptor remained open after cleanup")
	}
}

func TestFinishWriteTargetReportsCleanupFailureAfterSuccess(t *testing.T) {
	target, err := os.CreateTemp(t.TempDir(), "target-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishWriteTarget(nil, target, true)
	if err == nil {
		t.Fatal("cleanup failure after an otherwise successful write was ignored")
	}
	if !strings.Contains(err.Error(), "unlock target after writing") || !strings.Contains(err.Error(), "close target after writing") {
		t.Fatalf("cleanup failures were not preserved: %v", err)
	}
}

func TestFinishWriteTargetJoinsPriorCancellationAndCleanupFailure(t *testing.T) {
	target, err := os.CreateTemp(t.TempDir(), "target-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishWriteTarget(context.Canceled, target, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "unlock target after writing") || !strings.Contains(err.Error(), "close target after writing") {
		t.Fatalf("cleanup failure was not joined with cancellation: %v", err)
	}
}
