//go:build linux

package sourcefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadLeaseRejectsExistingWritableDescriptor(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	lease, err := AcquireReadLease(context.Background(), reader, identity)
	if lease != nil {
		lease.Close()
	}
	if !errors.Is(err, ErrReadLeaseConflict) {
		t.Fatalf("AcquireReadLease error = %v", err)
	}
}

func TestReadLeaseRejectsExistingWritableMapping(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := syscall.Mmap(int(writer.Fd()), 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		syscall.Munmap(mapping)
		t.Fatal(err)
	}
	defer syscall.Munmap(mapping)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	lease, err := AcquireReadLease(context.Background(), reader, identity)
	if lease != nil {
		lease.Close()
	}
	if !errors.Is(err, ErrReadLeaseConflict) {
		t.Fatalf("AcquireReadLease error = %v", err)
	}
}

func TestReadLeaseBreakCancelsOperation(t *testing.T) {
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

	writer, openErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if writer != nil {
		writer.Close()
	}
	if !errors.Is(openErr, syscall.EAGAIN) {
		lease.Close()
		t.Fatalf("conflicting writer error = %v", openErr)
	}
	select {
	case <-lease.Context().Done():
	case <-time.After(2 * time.Second):
		lease.Close()
		t.Fatal("lease break did not cancel operation")
	}
	if err := lease.Check(); !errors.Is(err, ErrReadLeaseBroken) {
		lease.Close()
		t.Fatalf("Check error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err = os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("writer after release: %v", err)
	}
	writer.Close()
}

func TestReadLeaseAllowsAdditionalReadOnlyOpen(t *testing.T) {
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
	defer lease.Close()

	second, err := os.Open(path)
	if err != nil {
		t.Fatalf("read-only open under lease: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestReadLeaseTruncateCancelsOperation(t *testing.T) {
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

	truncated := make(chan error, 1)
	go func() {
		truncated <- os.Truncate(path, 0)
	}()
	select {
	case <-lease.Context().Done():
	case err := <-truncated:
		lease.Close()
		t.Fatalf("truncate completed before lease release: %v", err)
	case <-time.After(2 * time.Second):
		lease.Close()
		t.Fatal("truncate did not request a lease break")
	}
	if err := lease.Check(); !errors.Is(err, ErrReadLeaseBroken) {
		lease.Close()
		t.Fatalf("Check error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-truncated:
		if err != nil {
			t.Fatalf("truncate after lease release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("truncate remained blocked after lease release")
	}
}

func TestReadLeaseStableAndReleases(t *testing.T) {
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
	if err := lease.Check(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadLeaseSlotHonoursContext(t *testing.T) {
	firstPath, firstIdentity := writeLeaseTestFile(t)
	firstReader, err := os.Open(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer firstReader.Close()
	first, err := AcquireReadLease(context.Background(), firstReader, firstIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	secondPath, secondIdentity := writeLeaseTestFile(t)
	secondReader, err := os.Open(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	defer secondReader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := AcquireReadLease(ctx, secondReader, secondIdentity)
	if lease != nil {
		lease.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("second lease error = %v", err)
	}
}

func TestReadLeaseRequiresPinnedIdentityAndReadOnlyDescriptor(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if lease, err := AcquireReadLease(context.Background(), writer, identity); lease != nil || err == nil {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("writable descriptor lease = %v, %v", lease, err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	identity.Size++
	if lease, err := AcquireReadLease(context.Background(), reader, identity); lease != nil || err == nil {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("altered identity lease = %v, %v", lease, err)
	}
}

func TestClassifyReadLeaseErrors(t *testing.T) {
	if err := classifyReadLeaseError(syscall.EAGAIN); !errors.Is(err, ErrReadLeaseConflict) {
		t.Fatalf("EAGAIN classification = %v", err)
	}
	for _, value := range []error{syscall.EINVAL, syscall.ENOSYS, syscall.EOPNOTSUPP, syscall.EPERM, syscall.EACCES} {
		if err := classifyReadLeaseError(value); !errors.Is(err, ErrReadLeaseUnavailable) {
			t.Fatalf("%v classification = %v", value, err)
		}
	}
}

func writeLeaseTestFile(t *testing.T) (string, Identity) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.iso")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := IdentityOf(file)
	if err != nil {
		t.Fatal(err)
	}
	return path, identity
}
