//go:build linux

package persistence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
)

// FilesystemEvent reports the bounded stages used to create and initialize the
// persistence filesystem.
type FilesystemEvent struct {
	Stage   string
	Message string
}

// FilesystemOptions identity-binds the already-created partition descriptor.
// BeforeDestructive is called with that descriptor immediately before mkfs.
type FilesystemOptions struct {
	ExpectedDeviceID  uint64
	ExpectedSize      uint64
	BeforeDestructive func(partition *os.File) error
	WorkDirectory     string
	Event             func(FilesystemEvent)
}

// CreateFilesystem formats an already-created partition as ext4, initializes
// the live-boot contract, unmounts it, and performs a read-only filesystem
// check. The caller must have created and verified the partition table and must
// keep the parent whole-disk safety lock for the entire call.
func CreateFilesystem(ctx context.Context, partitionPath string, plan Plan, opts FilesystemOptions) (returnErr error) {
	if err := validateFilesystemPlan(plan); err != nil {
		return err
	}
	if strings.TrimSpace(partitionPath) == "" {
		return errors.New("persistence partition path is required")
	}
	info, err := os.Lstat(partitionPath)
	if err != nil {
		return fmt.Errorf("inspect persistence partition: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("persistence partition path is a symbolic link")
	}

	partition, err := os.OpenFile(partitionPath, os.O_RDWR|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open persistence partition: %w", err)
	}
	defer partition.Close()
	if err := verifyPersistencePartition(partition, partitionPath, plan, opts); err != nil {
		return err
	}
	if err := syscall.Flock(int(partition.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("lock persistence partition: %w", err)
	}
	defer syscall.Flock(int(partition.Fd()), syscall.LOCK_UN) // best effort

	for _, program := range []string{"mkfs.ext4", "mount", "umount", "e2fsck"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("required program %q is not installed", program)
		}
	}
	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = "/run"
	}
	mountDir, err := os.MkdirTemp(workRoot, "rufusarm64-persistence-")
	if err != nil {
		return fmt.Errorf("create persistence mount directory: %w", err)
	}
	if err := os.Chmod(mountDir, 0o700); err != nil {
		_ = os.RemoveAll(mountDir)
		return fmt.Errorf("secure persistence mount directory: %w", err)
	}
	mounted := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mounted {
			if err := runPartitionCommand(cleanupCtx, partition, "umount", "--", mountDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup persistence mount: %w", err))
			} else {
				mounted = false
			}
		}
		if !mounted {
			if err := os.RemoveAll(mountDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove persistence mount directory: %w", err))
			}
		}
	}()

	if opts.BeforeDestructive != nil {
		if err := opts.BeforeDestructive(partition); err != nil {
			return fmt.Errorf("final persistence partition safety check: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	emitFilesystem(opts.Event, "format", fmt.Sprintf("Formatting persistence partition as ext4 with label %q…", plan.FilesystemLabel))
	if err := runPartitionCommand(ctx, partition, "mkfs.ext4", "-F", "-L", plan.FilesystemLabel, "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0", partitionFDToken); err != nil {
		return fmt.Errorf("format persistence partition: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	emitFilesystem(opts.Event, "mount", "Mounting the new persistence filesystem with restricted options…")
	if err := runPartitionCommand(ctx, partition, "mount", "-t", "ext4", "-o", "nosuid,nodev,noexec", partitionFDToken, mountDir); err != nil {
		return fmt.Errorf("mount persistence filesystem: %w", err)
	}
	mounted = true
	if err := initializePersistenceRoot(mountDir, plan); err != nil {
		return err
	}
	if err := syncPersistenceRoot(mountDir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	emitFilesystem(opts.Event, "unmount", "Unmounting the initialized persistence filesystem…")
	if err := runPartitionCommand(ctx, partition, "umount", "--", mountDir); err != nil {
		return fmt.Errorf("unmount persistence filesystem: %w", err)
	}
	mounted = false
	emitFilesystem(opts.Event, "check", "Checking the persistence filesystem read-only…")
	if err := runPartitionCommand(ctx, partition, "e2fsck", "-f", "-n", partitionFDToken); err != nil {
		return fmt.Errorf("check persistence filesystem: %w", err)
	}
	if err := partition.Sync(); err != nil {
		return fmt.Errorf("sync persistence partition: %w", err)
	}
	emitFilesystem(opts.Event, "complete", "Persistence filesystem created and checked.")
	return nil
}

const partitionFDToken = "{partition-fd}"

func validateFilesystemPlan(plan Plan) error {
	if plan.Filesystem != "ext4" || plan.FilesystemLabel == "" || plan.SizeBytes < minimumPartitionSize {
		return errors.New("invalid persistence filesystem plan")
	}
	switch plan.Family {
	case FamilyUbuntuCasper:
		if plan.FilesystemLabel != "casper-rw" || plan.PersistenceConfig != "" {
			return errors.New("invalid Ubuntu casper persistence filesystem contract")
		}
	case FamilyDebianLive:
		if plan.FilesystemLabel != "persistence" || plan.PersistenceConfig != "/ union\n" {
			return errors.New("invalid Debian live-boot persistence filesystem contract")
		}
	default:
		return fmt.Errorf("unsupported persistence family %q", plan.Family)
	}
	return nil
}

func verifyPersistencePartition(partition *os.File, path string, plan Plan, opts FilesystemOptions) error {
	info, err := partition.Stat()
	if err != nil {
		return fmt.Errorf("stat persistence partition: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("persistence partition has no Linux device metadata")
	}
	if stat.Mode&syscall.S_IFMT == syscall.S_IFBLK {
		if opts.ExpectedDeviceID == 0 || opts.ExpectedSize == 0 {
			return errors.New("persistence block-device identity and size are required")
		}
		if err := safety.VerifyOpenDevice(partition, opts.ExpectedDeviceID, opts.ExpectedSize); err != nil {
			return err
		}
		if opts.ExpectedSize != plan.SizeBytes {
			return errors.New("persistence partition size does not match the plan")
		}
		return nil
	}
	// Test-only regular files are accepted only when the exact path is explicitly
	// selected by the test harness, mirroring the existing Windows-media tests.
	if os.Getenv("RUFUS_TEST_PARTITION") == path && info.Mode().IsRegular() {
		if uint64(info.Size()) != plan.SizeBytes {
			return errors.New("test persistence partition size does not match the plan")
		}
		return nil
	}
	return safety.ErrNotBlockDevice
}

func initializePersistenceRoot(root string, plan Plan) error {
	if plan.PersistenceConfig == "" {
		return nil
	}
	rootHandle, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open persistence filesystem root: %w", err)
	}
	defer syscall.Close(rootHandle)
	fd, err := syscall.Openat(rootHandle, "persistence.conf", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("create persistence.conf: %w", err)
	}
	file := os.NewFile(uintptr(fd), "persistence.conf")
	if file == nil {
		syscall.Close(fd)
		return errors.New("create persistence.conf handle")
	}
	if _, err := io.WriteString(file, plan.PersistenceConfig); err != nil {
		file.Close()
		return fmt.Errorf("write persistence.conf: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync persistence.conf: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close persistence.conf: %w", err)
	}
	if err := syscall.Fsync(rootHandle); err != nil {
		return fmt.Errorf("sync persistence filesystem root: %w", err)
	}
	return nil
}

func syncPersistenceRoot(root string) error {
	directory, err := os.Open(root)
	if err != nil {
		return fmt.Errorf("open persistence root for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync persistence filesystem: %w", err)
	}
	return nil
}

func runPartitionCommand(ctx context.Context, partition *os.File, name string, arguments ...string) error {
	args := append([]string(nil), arguments...)
	for index, argument := range args {
		if argument == partitionFDToken {
			args[index] = "/proc/self/fd/3"
		}
	}
	command := exec.CommandContext(ctx, name, args...)
	command.ExtraFiles = []*os.File{partition}
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, message)
	}
	return nil
}

func emitFilesystem(event func(FilesystemEvent), stage, message string) {
	if event != nil {
		event(FilesystemEvent{Stage: stage, Message: message})
	}
}
