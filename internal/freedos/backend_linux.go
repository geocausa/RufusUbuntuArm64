//go:build linux

package freedos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/safety"
)

// LinuxDeviceOptions binds the production backend to one already reviewed
// kernel block device. Revalidate must refresh host policy and identity from
// live kernel state; it runs after locking, immediately before the first write,
// and again after required-extent readback.
type LinuxDeviceOptions struct {
	ExpectedDeviceID uint64
	ExpectedSize     uint64
	Revalidate       func(*os.File) error
}

// ExecuteLinuxDevice runs the guarded execution state machine through the
// Linux block-device backend. It does not perform discovery, confirmation, or
// authentication; callers must complete those boundaries before invoking it.
func ExecuteLinuxDevice(ctx context.Context, plan DevicePlan, options LinuxDeviceOptions, execution ExecutionOptions) (ExecutionReport, error) {
	if options.ExpectedDeviceID == 0 {
		return ExecutionReport{}, errors.New("FreeDOS Linux backend requires a bound kernel device identity")
	}
	if options.Revalidate == nil {
		return ExecutionReport{}, errors.New("FreeDOS Linux backend requires a live policy and identity callback")
	}
	if options.ExpectedSize == 0 {
		options.ExpectedSize = plan.DeviceSizeBytes
	}
	if options.ExpectedSize != plan.DeviceSizeBytes {
		return ExecutionReport{}, errors.New("FreeDOS Linux backend size does not match the reviewed plan")
	}
	backend := &linuxDeviceBackend{options: options}
	return ExecuteDevicePlan(ctx, plan, backend, execution)
}

type linuxDeviceBackend struct {
	options    LinuxDeviceOptions
	target     *os.File
	stablePath string
	locked     bool
}

func (backend *linuxDeviceBackend) Prepare(ctx context.Context, plan DevicePlan) error {
	for _, program := range []string{"blockdev", "sync"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("required program %q is not installed", program)
		}
	}
	resolved, err := safety.ResolveDevice(plan.DevicePath)
	if err != nil {
		return err
	}
	if resolved != plan.DevicePath {
		return fmt.Errorf("FreeDOS target must be a resolved whole-device path, not %s", plan.DevicePath)
	}
	file, err := safety.OpenReopenableDevice(plan.DevicePath)
	if err != nil {
		return fmt.Errorf("open FreeDOS target: %w", err)
	}
	backend.target = file
	backend.stablePath = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
	if err := safety.AcquireExclusiveFlock(ctx, file); err != nil {
		return fmt.Errorf("acquire exclusive FreeDOS target lock: %w", err)
	}
	backend.locked = true
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
		return err
	}
	if err := backend.options.Revalidate(file); err != nil {
		return fmt.Errorf("initial FreeDOS target revalidation: %w", err)
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxDeviceBackend) BeforeDestructive(_ context.Context, plan DevicePlan) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
		return err
	}
	if err := backend.options.Revalidate(backend.target); err != nil {
		return fmt.Errorf("final FreeDOS target revalidation: %w", err)
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxDeviceBackend) TargetWriterAt() io.WriterAt {
	return backend.target
}

func (backend *linuxDeviceBackend) Flush(ctx context.Context, plan DevicePlan) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := backend.target.Sync(); err != nil {
		return fmt.Errorf("sync FreeDOS target: %w", err)
	}
	if _, err := runLinuxDeviceCommand(ctx, "blockdev", "--flushbufs", backend.stablePath); err != nil {
		return fmt.Errorf("flush FreeDOS block buffers: %w", err)
	}
	if _, err := runLinuxDeviceCommand(ctx, "sync"); err != nil {
		return fmt.Errorf("synchronize FreeDOS target: %w", err)
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxDeviceBackend) TargetReaderAt() io.ReaderAt {
	return backend.target
}

func (backend *linuxDeviceBackend) Finish(ctx context.Context, plan DevicePlan) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
		return err
	}
	if err := backend.options.Revalidate(backend.target); err != nil {
		return fmt.Errorf("final FreeDOS target identity check: %w", err)
	}
	if err := backend.target.Sync(); err != nil {
		return fmt.Errorf("final FreeDOS target sync: %w", err)
	}
	if _, err := runLinuxDeviceCommand(ctx, "blockdev", "--flushbufs", backend.stablePath); err != nil {
		return fmt.Errorf("final FreeDOS buffer flush: %w", err)
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxDeviceBackend) Close() error {
	if backend.target == nil {
		return nil
	}
	var result error
	if backend.locked {
		if err := syscall.Flock(int(backend.target.Fd()), syscall.LOCK_UN); err != nil {
			result = errors.Join(result, fmt.Errorf("unlock FreeDOS target: %w", err))
		}
	}
	if err := backend.target.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close FreeDOS target: %w", err))
	}
	backend.target = nil
	backend.stablePath = ""
	backend.locked = false
	return result
}

func (backend *linuxDeviceBackend) verifyTarget(plan DevicePlan) error {
	if backend.target == nil {
		return errors.New("FreeDOS target is not open")
	}
	if err := safety.VerifyOpenDevice(backend.target, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes); err != nil {
		return err
	}
	pathID, err := safety.KernelDeviceID(plan.DevicePath)
	if err != nil {
		return fmt.Errorf("revalidate FreeDOS target path: %w", err)
	}
	if pathID != backend.options.ExpectedDeviceID {
		return errors.New("the FreeDOS target path now names a different kernel device")
	}
	return nil
}

func runLinuxDeviceCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
