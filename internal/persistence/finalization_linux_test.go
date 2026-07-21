//go:build linux

package persistence

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestFinishPersistenceFileCleanlyUnlocksAndCloses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistence-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := finishPersistenceFile(nil, file, true, "test partition"); err != nil {
		t.Fatalf("clean finalization failed: %v", err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("descriptor remained open after finalization")
	}
}

func TestFinishPersistenceFileReportsUnlockAndCloseFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistence-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishPersistenceFile(nil, file, true, "test partition")
	if err == nil {
		t.Fatal("finalization failure was ignored")
	}
	if !strings.Contains(err.Error(), "unlock test partition") || !strings.Contains(err.Error(), "close test partition") {
		t.Fatalf("finalization errors were not preserved: %v", err)
	}
}

func TestFinishPersistenceFilePreservesPriorCancellation(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "persistence-")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishPersistenceFile(context.Canceled, file, true, "test partition")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "unlock test partition") || !strings.Contains(err.Error(), "close test partition") {
		t.Fatalf("finalization errors were not joined: %v", err)
	}
}

func TestEmitFilesystemCompletionOnlyAfterCleanFinalization(t *testing.T) {
	var events []FilesystemEvent
	emit := func(event FilesystemEvent) { events = append(events, event) }

	emitFilesystemCompletion(false, nil, emit)
	emitFilesystemCompletion(true, errors.New("cleanup failed"), emit)
	if len(events) != 0 {
		t.Fatalf("completion emitted for an incomplete or failed operation: %#v", events)
	}

	emitFilesystemCompletion(true, nil, emit)
	if len(events) != 1 || events[0].Stage != "complete" {
		t.Fatalf("clean completion event missing or malformed: %#v", events)
	}
}
