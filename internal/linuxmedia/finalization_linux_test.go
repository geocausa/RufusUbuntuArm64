//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestFinishPersistentFileCleanlyUnlocksAndCloses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistent-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := finishPersistentFile(nil, file, true, "test target"); err != nil {
		t.Fatalf("clean finalization failed: %v", err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("descriptor remained open after finalization")
	}
}

func TestFinishPersistentFileReportsUnlockAndCloseFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistent-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishPersistentFile(nil, file, true, "test target")
	if err == nil {
		t.Fatal("finalization failure was ignored")
	}
	if !strings.Contains(err.Error(), "unlock test target") || !strings.Contains(err.Error(), "close test target") {
		t.Fatalf("finalization errors were not preserved: %v", err)
	}
}

func TestFinishPersistentFilePreservesPriorCancellation(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistent-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishPersistentFile(context.Canceled, file, true, "test target")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "unlock test target") || !strings.Contains(err.Error(), "close test target") {
		t.Fatalf("finalization errors were not joined: %v", err)
	}
}

func TestEmitPersistentCompletionOnlyAfterCleanFinalization(t *testing.T) {
	var events []PersistentEvent
	emit := func(event PersistentEvent) { events = append(events, event) }

	emitPersistentCompletion(false, nil, emit)
	emitPersistentCompletion(true, errors.New("cleanup failed"), emit)
	if len(events) != 0 {
		t.Fatalf("completion emitted for an incomplete or failed operation: %#v", events)
	}

	emitPersistentCompletion(true, nil, emit)
	if len(events) != 1 || events[0].Stage != "complete" {
		t.Fatalf("clean completion event missing or malformed: %#v", events)
	}
}
