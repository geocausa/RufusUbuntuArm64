//go:build linux

package safety

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAcquireExclusiveFlockWaitsForTransientHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Flock(int(first.Fd()), syscall.LOCK_UN)
		close(released)
	}()
	if err := AcquireExclusiveFlock(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(second.Fd()), syscall.LOCK_UN)
	<-released
}

func TestAcquireExclusiveFlockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(first.Fd()), syscall.LOCK_UN)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AcquireExclusiveFlock(ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestAcquireExclusiveFlockRejectsNilFile(t *testing.T) {
	if err := AcquireExclusiveFlock(context.Background(), nil); err == nil {
		t.Fatal("expected nil file error")
	}
}
