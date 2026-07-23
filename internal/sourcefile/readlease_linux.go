//go:build linux

package sourcefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	ErrReadLeaseUnavailable = errors.New("source read lease is unavailable")
	ErrReadLeaseConflict    = errors.New("source read lease conflicts with existing writable access")
	ErrReadLeaseBroken      = errors.New("source read lease was broken")
)

var readLeaseSlot = make(chan struct{}, 1)

// ReadLease holds a Linux read lease on one already-open regular source file.
// It prevents new writable opens and truncation while the holder remains
// active. Callers must still hash the exact bytes once; the lease replaces
// repeated stability hashes, not content authentication.
type ReadLease struct {
	file      *os.File
	ctx       context.Context
	cancel    context.CancelCauseFunc
	signals   chan os.Signal
	stop      chan struct{}
	done      chan struct{}
	breakMu   sync.Mutex
	breakErr  error
	closeOnce sync.Once
	closeErr  error
}

// AcquireReadLease revalidates the complete originally selected source
// identity, including ctime, then acquires a process-owned Linux read lease.
// Unsupported filesystems and existing writable access are reported with
// errors that callers may use to select the conservative hash-based path.
func AcquireReadLease(parent context.Context, file *os.File, expected Identity) (*ReadLease, error) {
	if parent == nil {
		return nil, errors.New("source read lease context is nil")
	}
	if file == nil {
		return nil, errors.New("source read lease file is nil")
	}
	if err := Verify(file, expected); err != nil {
		return nil, err
	}
	flags, err := fcntlInt(file.Fd(), syscall.F_GETFL, 0)
	if err != nil {
		return nil, fmt.Errorf("read source descriptor flags: %w", err)
	}
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return nil, errors.New("source read lease requires a read-only descriptor")
	}
	select {
	case readLeaseSlot <- struct{}{}:
	case <-parent.Done():
		return nil, context.Cause(parent)
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			<-readLeaseSlot
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGIO)
	cleanupSignals := true
	defer func() {
		if cleanupSignals {
			signal.Stop(signals)
		}
	}()
	if _, err := fcntlInt(file.Fd(), syscall.F_SETOWN, os.Getpid()); err != nil {
		return nil, fmt.Errorf("%w: configure lease-break owner: %v", ErrReadLeaseUnavailable, err)
	}
	if _, err := fcntlInt(file.Fd(), syscall.F_SETLEASE, syscall.F_RDLCK); err != nil {
		return nil, classifyReadLeaseError(err)
	}
	leaseHeld := true
	defer func() {
		if leaseHeld {
			_, _ = fcntlInt(file.Fd(), syscall.F_SETLEASE, syscall.F_UNLCK)
		}
	}()
	state, err := fcntlInt(file.Fd(), syscall.F_GETLEASE, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: confirm acquired lease: %v", ErrReadLeaseUnavailable, err)
	}
	if state != syscall.F_RDLCK {
		return nil, fmt.Errorf("%w: acquired state is %d", ErrReadLeaseUnavailable, state)
	}

	ctx, cancel := context.WithCancelCause(parent)
	lease := &ReadLease{
		file:    file,
		ctx:     ctx,
		cancel:  cancel,
		signals: signals,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go lease.watch()
	releaseSlot = false
	cleanupSignals = false
	leaseHeld = false
	return lease, nil
}

// Context is cancelled with ErrReadLeaseBroken when another process requests
// conflicting writable access. It also retains cancellation from the parent.
func (lease *ReadLease) Context() context.Context {
	if lease == nil {
		return nil
	}
	return lease.ctx
}

// Check confirms that no lease break has been requested or forced.
func (lease *ReadLease) Check() error {
	if lease == nil || lease.file == nil {
		return errors.New("source read lease is nil")
	}
	if err := lease.breakCause(); err != nil {
		return err
	}
	if err := lease.ctx.Err(); err != nil {
		return context.Cause(lease.ctx)
	}
	state, err := fcntlInt(lease.file.Fd(), syscall.F_GETLEASE, 0)
	if err != nil {
		return lease.markBroken(fmt.Errorf("%w: query lease: %v", ErrReadLeaseBroken, err))
	}
	if state != syscall.F_RDLCK {
		return lease.markBroken(fmt.Errorf("%w: state changed to %d", ErrReadLeaseBroken, state))
	}
	return nil
}

// Close releases the lease, signal registration, and process-wide lease slot.
// It never closes the caller-owned source descriptor.
func (lease *ReadLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.closeOnce.Do(func() {
		// Keep SIGIO registered until the kernel lease is gone. Otherwise a
		// conflicting writer arriving during cleanup could target the process
		// after its lease-break handler had already been removed.
		if _, err := fcntlInt(lease.file.Fd(), syscall.F_SETLEASE, syscall.F_UNLCK); err != nil {
			lease.closeErr = fmt.Errorf("release source read lease: %w", err)
		}
		signal.Stop(lease.signals)
		close(lease.stop)
		<-lease.done
		lease.cancel(context.Canceled)
		<-readLeaseSlot
	})
	return lease.closeErr
}

func (lease *ReadLease) watch() {
	defer close(lease.done)
	for {
		select {
		case <-lease.stop:
			return
		case <-lease.signals:
			// The notification itself means a conflicting writable open or
			// truncate was requested. Fail closed immediately even if an
			// adjacent F_GETLEASE query still observes the pre-break state.
			state, err := fcntlInt(lease.file.Fd(), syscall.F_GETLEASE, 0)
			if err != nil {
				lease.markBroken(fmt.Errorf("%w: break notification; state query failed: %v", ErrReadLeaseBroken, err))
			} else {
				lease.markBroken(fmt.Errorf("%w: break requested; observed state %d", ErrReadLeaseBroken, state))
			}
			return
		}
	}
}

func (lease *ReadLease) markBroken(cause error) error {
	if cause == nil {
		cause = ErrReadLeaseBroken
	}
	lease.breakMu.Lock()
	defer lease.breakMu.Unlock()
	if lease.breakErr == nil {
		lease.breakErr = cause
		lease.cancel(cause)
	}
	return lease.breakErr
}

func (lease *ReadLease) breakCause() error {
	lease.breakMu.Lock()
	defer lease.breakMu.Unlock()
	return lease.breakErr
}

func classifyReadLeaseError(err error) error {
	switch {
	case errors.Is(err, syscall.EAGAIN):
		return fmt.Errorf("%w: %v", ErrReadLeaseConflict, err)
	case errors.Is(err, syscall.EINVAL),
		errors.Is(err, syscall.ENOSYS),
		errors.Is(err, syscall.EOPNOTSUPP),
		errors.Is(err, syscall.EPERM),
		errors.Is(err, syscall.EACCES):
		return fmt.Errorf("%w: %v", ErrReadLeaseUnavailable, err)
	default:
		return fmt.Errorf("acquire source read lease: %w", err)
	}
}

func fcntlInt(fd uintptr, command, argument int) (int, error) {
	value, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(command), uintptr(argument))
	if errno != 0 {
		return 0, errno
	}
	return int(value), nil
}
