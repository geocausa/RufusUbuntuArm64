//go:build linux

package sourcefile

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestReadLeaseParentCancellationRetainsLeaseUntilClose(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	lease, err := AcquireReadLease(ctx, reader, identity)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-lease.Context().Done():
	case <-time.After(2 * time.Second):
		lease.Close()
		t.Fatal("parent cancellation did not reach lease context")
	}
	writer, openErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if writer != nil {
		writer.Close()
	}
	if !errors.Is(openErr, syscall.EAGAIN) {
		lease.Close()
		t.Fatalf("writer was not blocked during cancellation cleanup: %v", openErr)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err = os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("writer after cancellation cleanup: %v", err)
	}
	writer.Close()
}

func TestReadLeaseBreakNotificationFailsClosedBeforeStateChange(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	lease, err := AcquireReadLease(context.Background(), reader, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGIO); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	select {
	case <-lease.Context().Done():
	case <-time.After(2 * time.Second):
		lease.Close()
		t.Fatal("lease-break notification did not cancel operation")
	}
	if err := lease.Check(); !errors.Is(err, ErrReadLeaseBroken) {
		lease.Close()
		t.Fatalf("Check error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}
