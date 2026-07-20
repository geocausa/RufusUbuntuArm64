//go:build linux

package nonbootable

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFormatterUsesAuditedReopenableWholeDiskContract(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate formatter source")
	}
	directory := filepath.Dir(current)
	backendContent, err := os.ReadFile(filepath.Join(directory, "backend_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	bindingContent, err := os.ReadFile(filepath.Join(directory, "binding_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	backend := string(backendContent)
	binding := string(bindingContent)
	openIndex := strings.Index(backend, "safety.OpenReopenableDevice(plan.DevicePath)")
	stableIndex := strings.Index(backend, "backend.stableTargetPath = stableDescriptorPath(file)")
	lockIndex := strings.Index(backend, "safety.AcquireExclusiveFlock(ctx, file)")
	verifyIndex := strings.Index(backend, "safety.VerifyOpenDevice(file, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes)")
	callbackIndex := strings.Index(backend, "backend.options.BeforeDestructive(file)")
	if openIndex < 0 || stableIndex < openIndex || lockIndex < stableIndex || verifyIndex < lockIndex || callbackIndex < verifyIndex {
		t.Fatal("formatter target sequence is not open -> stable path -> lock -> verify -> final callback")
	}
	if strings.Contains(backend, "os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_EXCL") {
		t.Fatal("formatter must not hold O_EXCL while trusted filesystem tools reopen partitions")
	}
	for _, fragment := range []string{
		`"wipefs", "--all", "--force", "--", backend.stableTargetPath`,
		`"sfdisk", "--no-reread", "--force", "--wipe", "always", "--wipe-partitions", "always", "--", backend.stableTargetPath`,
		`"blockdev", "--rereadpt", backend.stableTargetPath`,
		`args = append(args, backend.stablePartitionPath)`,
		`safety.WithTemporarilyReleasedFlock(backend.partition`,
		`filesystemCheck(plan.Filesystem, backend.stablePartitionPath)`,
		`readBlkid(ctx, backend.stablePartitionPath)`,
		`"blockdev", "--flushbufs", backend.stableTargetPath`,
		`syscall.Flock(int(backend.target.Fd()), syscall.LOCK_UN)`,
	} {
		if !strings.Contains(backend, fragment) {
			t.Fatalf("formatter backend is missing descriptor-bound contract %q", fragment)
		}
	}
	for _, forbidden := range []string{
		`"wipefs", "--all", "--force", "--", plan.DevicePath`,
		`"sfdisk", "--no-reread", "--force", "--wipe", "always", "--wipe-partitions", "always", "--", plan.DevicePath`,
		`args = append(args, partitionPath)`,
	} {
		if strings.Contains(backend, forbidden) {
			t.Fatalf("formatter destructive tool still uses a mutable pathname: %q", forbidden)
		}
	}
	for _, fragment := range []string{
		`fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())`,
		`safety.KernelDeviceID(plan.DevicePath)`,
		`safety.OpenReopenableDevice(partitionPath)`,
		`safety.AcquireExclusiveFlock(ctx, partition)`,
		`safety.VerifyOpenDevice(partition, deviceID, plan.PartitionSizeBytes)`,
		`safety.KernelDeviceID(partitionPath)`,
		`backend.closePartition()`,
	} {
		if !strings.Contains(binding, fragment) {
			t.Fatalf("formatter binding source is missing %q", fragment)
		}
	}
}
