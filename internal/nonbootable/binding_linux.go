//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/safety"
)

func stableDescriptorPath(file *os.File) string {
	if file == nil {
		return ""
	}
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
}

func (backend *linuxBackend) verifyTargetPath(plan Plan) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if backend.options.ExpectedDeviceID == 0 || backend.stableTargetPath == "" {
		return errors.New("formatter target is missing its bound kernel identity or stable descriptor path")
	}
	currentID, err := safety.KernelDeviceID(plan.DevicePath)
	if err != nil {
		return fmt.Errorf("revalidate target pathname: %w", err)
	}
	if currentID != backend.options.ExpectedDeviceID {
		return fmt.Errorf("target pathname now resolves to kernel device %d, expected %d", currentID, backend.options.ExpectedDeviceID)
	}
	return nil
}

func (backend *linuxBackend) bindPartition(ctx context.Context, partitionPath string, plan Plan, table PartitionTable) (returnErr error) {
	if backend.partition != nil {
		return errors.New("formatter partition is already bound")
	}
	if err := backend.verifyTargetPath(plan); err != nil {
		return err
	}
	if err := verifyKernelPartition(partitionPath, plan, table); err != nil {
		return err
	}
	deviceID, err := safety.KernelDeviceID(partitionPath)
	if err != nil {
		return fmt.Errorf("read formatter partition identity: %w", err)
	}
	partition, err := safety.OpenReopenableDevice(partitionPath)
	if err != nil {
		return fmt.Errorf("open formatter partition: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = partition.Close()
		}
	}()
	if err := safety.AcquireExclusiveFlock(ctx, partition); err != nil {
		return fmt.Errorf("lock formatter partition: %w", err)
	}
	locked := true
	defer func() {
		if returnErr != nil && locked {
			_ = syscall.Flock(int(partition.Fd()), syscall.LOCK_UN)
		}
	}()
	if err := safety.VerifyOpenDevice(partition, deviceID, plan.PartitionSizeBytes); err != nil {
		return err
	}
	if err := verifyKernelPartition(partitionPath, plan, table); err != nil {
		return err
	}
	backend.partition = partition
	backend.partitionPath = partitionPath
	backend.stablePartitionPath = stableDescriptorPath(partition)
	backend.partitionDeviceID = deviceID
	backend.partitionLocked = true
	locked = false
	return backend.verifyPartitionPath(plan, partitionPath)
}

func (backend *linuxBackend) verifyPartitionPath(plan Plan, partitionPath string) error {
	if backend.partition == nil || !backend.partitionLocked || backend.stablePartitionPath == "" {
		return errors.New("formatter partition is not open and locked")
	}
	if partitionPath == "" || partitionPath != backend.partitionPath {
		return errors.New("formatter partition path does not match the bound partition")
	}
	if backend.partitionDeviceID == 0 {
		return errors.New("formatter partition is missing its kernel identity")
	}
	if err := safety.VerifyOpenDevice(backend.partition, backend.partitionDeviceID, plan.PartitionSizeBytes); err != nil {
		return err
	}
	currentID, err := safety.KernelDeviceID(partitionPath)
	if err != nil {
		return fmt.Errorf("revalidate formatter partition pathname: %w", err)
	}
	if currentID != backend.partitionDeviceID {
		return fmt.Errorf("formatter partition pathname now resolves to kernel device %d, expected %d", currentID, backend.partitionDeviceID)
	}
	table, err := BuildPartitionTable(plan)
	if err != nil {
		return err
	}
	return verifyKernelPartition(partitionPath, plan, table)
}

func (backend *linuxBackend) closePartition() error {
	if backend.partition == nil {
		return nil
	}
	var result error
	if backend.partitionLocked {
		if err := syscall.Flock(int(backend.partition.Fd()), syscall.LOCK_UN); err != nil {
			result = errors.Join(result, fmt.Errorf("unlock formatter partition: %w", err))
		}
	}
	if err := backend.partition.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close formatter partition: %w", err))
	}
	backend.partition = nil
	backend.partitionPath = ""
	backend.stablePartitionPath = ""
	backend.partitionDeviceID = 0
	backend.partitionLocked = false
	return result
}
