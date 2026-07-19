//go:build linux

package devicequal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

const (
	blkflsbuf                 = 0x1261
	qualificationLockWait     = 2 * time.Second
	qualificationLockInterval = 50 * time.Millisecond
)

// DeviceOptions binds a qualification run to an already validated whole-device
// identity. The caller remains responsible for removable/system-disk policy,
// confirmation, and unmounting before RunDevice is called.
type DeviceOptions struct {
	ExpectedDeviceID uint64
	ExpectedSize     uint64
	Profile          Profile
	RegionSize       uint64
	BufferSize       int
	Patterns         []Pattern
	Progress         ProgressFunc
	BeforeWrite      func(*os.File) error
}

// RunDevice opens and exclusively locks the exact selected block device, checks
// its live kernel identity and capacity, performs one final caller-supplied
// safety check, then runs the qualification engine through the held descriptor.
func RunDevice(ctx context.Context, path string, options DeviceOptions) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("device qualification context is nil")
	}
	if path == "" {
		return Report{}, errors.New("device qualification path is empty")
	}
	if options.ExpectedDeviceID == 0 {
		return Report{}, errors.New("expected kernel device identity is required")
	}
	if options.ExpectedSize == 0 {
		return Report{}, errors.New("expected device capacity is required")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Report{}, fmt.Errorf("open qualification target: %w", err)
	}
	defer func() { _ = file.Close() }()

	if err := safety.VerifyOpenDevice(file, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return Report{}, err
	}
	if err := acquireExclusiveFlock(ctx, file); err != nil {
		return Report{}, fmt.Errorf("acquire exclusive qualification lock on target: %w", err)
	}
	defer func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }()

	if options.BeforeWrite != nil {
		if err := options.BeforeWrite(file); err != nil {
			return Report{}, fmt.Errorf("final qualification target safety check: %w", err)
		}
	}
	if err := safety.VerifyOpenDevice(file, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return Report{}, err
	}

	backend := &flushedDeviceBackend{
		ctx:              ctx,
		file:             file,
		expectedDeviceID: options.ExpectedDeviceID,
		expectedSize:     options.ExpectedSize,
	}
	report, runErr := Run(ctx, backend, options.ExpectedSize, Config{
		Profile:    options.Profile,
		RegionSize: options.RegionSize,
		BufferSize: options.BufferSize,
		Patterns:   options.Patterns,
		Progress:   options.Progress,
	})
	if runErr != nil {
		return report, runErr
	}
	if err := safety.VerifyOpenDevice(file, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return report, err
	}
	return report, nil
}

func acquireExclusiveFlock(ctx context.Context, file *os.File) error {
	if ctx == nil {
		return errors.New("qualification lock context is nil")
	}
	if file == nil {
		return errors.New("qualification lock target is nil")
	}

	deadline := time.NewTimer(qualificationLockWait)
	defer deadline.Stop()
	retry := time.NewTicker(qualificationLockInterval)
	defer retry.Stop()

	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return err
		case <-retry.C:
		}
	}
}

type flushedDeviceBackend struct {
	ctx              context.Context
	file             *os.File
	expectedDeviceID uint64
	expectedSize     uint64
}

func (backend *flushedDeviceBackend) ReadAt(buffer []byte, offset int64) (int, error) {
	return backend.file.ReadAt(buffer, offset)
}

func (backend *flushedDeviceBackend) WriteAt(buffer []byte, offset int64) (int, error) {
	return backend.file.WriteAt(buffer, offset)
}

func (backend *flushedDeviceBackend) Sync() error {
	if err := backend.ctx.Err(); err != nil {
		return err
	}
	if err := backend.file.Sync(); err != nil {
		return fmt.Errorf("sync qualification target: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, backend.file.Fd(), uintptr(blkflsbuf), 0)
	if errno != 0 {
		return fmt.Errorf("flush qualification target buffers: %w", errno)
	}
	return safety.VerifyOpenDevice(backend.file, backend.expectedDeviceID, backend.expectedSize)
}
