//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAcquireExtractedTargetLockRetriesTransientContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	candidate, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()

	released := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
		close(released)
	}()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := acquireExtractedTargetLock(ctx, candidate, path); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(candidate.Fd()), syscall.LOCK_UN)
	<-released
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond {
		t.Fatalf("lock retry returned before the holder released it: %v", elapsed)
	}
}

func TestAcquireExtractedTargetLockHonoursCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
	candidate, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err = acquireExtractedTargetLock(ctx, candidate, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lock cancellation error=%v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancelled lock acquisition took too long: %v", elapsed)
	}
}
