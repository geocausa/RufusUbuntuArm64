//go:build linux

package drivebackup

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/geocausa/RufusArm64/internal/safety"
)

const (
	renameNoReplace   = 1
	sysRenameat2AMD64 = 316
	sysRenameat2ARM64 = 276
)

// DeviceOptions binds a capture to one already validated whole-device identity.
// The caller remains responsible for removable/system-disk policy, coherent
// mount-state handling, and user confirmation before CaptureDevice is called.
type DeviceOptions struct {
	ExpectedDeviceID uint64
	ExpectedSize     uint64
	BufferSize       int
	Progress         ProgressFunc
	BeforeRead       func(*os.File) error
}

type destinationPlan struct {
	path      string
	name      string
	directory *os.File
}

// CaptureDevice holds one read-only, exclusive block-device descriptor for the
// complete capture. Output is written to an owner-only same-directory temporary
// file and published without replacement only after copy, hash, sync, close,
// and final source revalidation all succeed.
func CaptureDevice(ctx context.Context, sourcePath, outputPath string, options DeviceOptions) (Report, error) {
	report := Report{Schema: ReportSchema, Status: StatusFailed, PlannedBytes: options.ExpectedSize}
	if ctx == nil {
		return fail(report, "invalid_context", 0, false, errors.New("backup context is nil"))
	}
	if sourcePath == "" {
		return fail(report, "invalid_source", 0, false, errors.New("backup source path is empty"))
	}
	if options.ExpectedDeviceID == 0 {
		return fail(report, "invalid_source", 0, false, errors.New("expected kernel device identity is required"))
	}
	if options.ExpectedSize == 0 {
		return fail(report, "invalid_size", 0, false, errors.New("expected device capacity is required"))
	}
	if err := ctx.Err(); err != nil {
		return cancel(report, 0, err)
	}

	destination, err := prepareDestination(outputPath, sourcePath, options.ExpectedSize)
	if err != nil {
		return fail(report, "destination_preflight", 0, false, err)
	}
	defer func() { _ = destination.directory.Close() }()

	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(report, "open_source", 0, false, fmt.Errorf("open backup source: %w", err))
	}
	defer func() { _ = source.Close() }()

	if err := safety.VerifyOpenDevice(source, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return fail(report, "source_identity", 0, false, err)
	}
	if options.BeforeRead != nil {
		if err := options.BeforeRead(source); err != nil {
			return fail(report, "source_safety", 0, false, fmt.Errorf("final backup source safety check: %w", err))
		}
	}
	if err := safety.VerifyOpenDevice(source, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return fail(report, "source_identity", 0, false, err)
	}

	temporary, temporaryName, err := destination.createTemporary()
	if err != nil {
		return fail(report, "open_destination", 0, false, err)
	}
	defer func() { _ = syscall.Unlinkat(int(destination.directory.Fd()), temporaryName) }()

	report, copyErr := Copy(ctx, source, temporary, options.ExpectedSize, Config{
		BufferSize: options.BufferSize,
		Progress:   options.Progress,
	})
	closeErr := temporary.Close()
	if copyErr != nil {
		return report, copyErr
	}
	if closeErr != nil {
		return fail(report, "close_destination", report.CompletedBytes, true, fmt.Errorf("close backup temporary destination: %w", closeErr))
	}
	if err := safety.VerifyOpenDevice(source, options.ExpectedDeviceID, options.ExpectedSize); err != nil {
		return fail(report, "source_revalidation", report.CompletedBytes, true, err)
	}
	if err := destination.revalidatePath(); err != nil {
		return fail(report, "destination_revalidation", report.CompletedBytes, true, err)
	}
	if err := publishNoReplace(destination.directory, temporaryName, destination.name); err != nil {
		return fail(report, "publish_destination", report.CompletedBytes, true, err)
	}
	return report, nil
}

func prepareDestination(outputPath, sourcePath string, required uint64) (destinationPlan, error) {
	if outputPath == "" {
		return destinationPlan{}, errors.New("backup destination path is empty")
	}
	clean := filepath.Clean(outputPath)
	if !filepath.IsAbs(clean) {
		return destinationPlan{}, errors.New("backup destination path must be absolute")
	}
	name := filepath.Base(clean)
	if clean == string(filepath.Separator) || name == "." || !filepath.IsLocal(name) {
		return destinationPlan{}, errors.New("backup destination must name a local file")
	}
	parent := filepath.Dir(clean)
	pathInfo, err := os.Lstat(parent)
	if err != nil {
		return destinationPlan{}, fmt.Errorf("inspect backup destination directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return destinationPlan{}, errors.New("backup destination parent must be a real directory")
	}
	directory, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return destinationPlan{}, fmt.Errorf("open backup destination directory: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = directory.Close()
		}
	}()
	openInfo, err := directory.Stat()
	if err != nil {
		return destinationPlan{}, fmt.Errorf("inspect open backup destination directory: %w", err)
	}
	if !openInfo.IsDir() || !os.SameFile(pathInfo, openInfo) {
		return destinationPlan{}, errors.New("backup destination directory changed during validation")
	}
	descriptorPath := fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
	if err := safety.EnsurePathNotOnTarget(descriptorPath, sourcePath); err != nil {
		return destinationPlan{}, fmt.Errorf("validate backup destination storage: %w", err)
	}
	if err := ensureFreeSpace(directory, required); err != nil {
		return destinationPlan{}, err
	}
	if err := ensureDestinationAbsent(directory, name); err != nil {
		return destinationPlan{}, err
	}
	closeOnError = false
	return destinationPlan{path: clean, name: name, directory: directory}, nil
}

func (destination destinationPlan) revalidatePath() error {
	pathInfo, err := os.Lstat(filepath.Dir(destination.path))
	if err != nil {
		return fmt.Errorf("reinspect backup destination directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return errors.New("backup destination directory is no longer a real directory")
	}
	openInfo, err := destination.directory.Stat()
	if err != nil {
		return fmt.Errorf("reinspect open backup destination directory: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		return errors.New("backup destination directory changed before publication")
	}
	return nil
}

func ensureDestinationAbsent(directory *os.File, name string) error {
	fd, err := syscall.Openat(
		int(directory.Fd()),
		name,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0,
	)
	if err == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("backup destination already exists: %s", name)
	}
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return fmt.Errorf("backup destination already exists or cannot be inspected: %s: %w", name, err)
}

func ensureFreeSpace(directory *os.File, required uint64) error {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return fmt.Errorf("inspect backup destination free space: %w", err)
	}
	if stat.Bsize <= 0 {
		return errors.New("backup destination reported an invalid filesystem block size")
	}
	blockSize := uint64(stat.Bsize)
	availableBlocks := uint64(stat.Bavail)
	available := uint64(math.MaxUint64)
	if availableBlocks <= math.MaxUint64/blockSize {
		available = availableBlocks * blockSize
	}
	if available < required {
		return fmt.Errorf("backup destination has %d bytes available but %d bytes are required", available, required)
	}
	return nil
}

func (destination destinationPlan) createTemporary() (*os.File, string, error) {
	descriptorPath := fmt.Sprintf("/proc/self/fd/%d", destination.directory.Fd())
	temporary, err := os.CreateTemp(descriptorPath, "."+destination.name+".rufusarm64-partial-*")
	if err != nil {
		return nil, "", fmt.Errorf("create backup temporary destination: %w", err)
	}
	name := filepath.Base(temporary.Name())
	if !filepath.IsLocal(name) {
		_ = temporary.Close()
		_ = os.Remove(temporary.Name())
		return nil, "", errors.New("backup temporary destination has an invalid name")
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		_ = syscall.Unlinkat(int(destination.directory.Fd()), name)
		return nil, "", fmt.Errorf("inspect backup temporary destination: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = temporary.Close()
		_ = syscall.Unlinkat(int(destination.directory.Fd()), name)
		return nil, "", errors.New("backup temporary destination is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			_ = syscall.Unlinkat(int(destination.directory.Fd()), name)
			return nil, "", fmt.Errorf("secure backup temporary destination: %w", err)
		}
	}
	return temporary, name, nil
}

func publishNoReplace(directory *os.File, temporaryName, outputName string) error {
	syscallNumber, err := renameat2SyscallNumber()
	if err != nil {
		return err
	}
	temporaryPointer, err := syscall.BytePtrFromString(temporaryName)
	if err != nil {
		return fmt.Errorf("encode backup temporary name: %w", err)
	}
	outputPointer, err := syscall.BytePtrFromString(outputName)
	if err != nil {
		return fmt.Errorf("encode backup destination name: %w", err)
	}
	directoryFD := uintptr(directory.Fd())
	_, _, errno := syscall.Syscall6(
		syscallNumber,
		directoryFD,
		uintptr(unsafe.Pointer(temporaryPointer)),
		directoryFD,
		uintptr(unsafe.Pointer(outputPointer)),
		renameNoReplace,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("publish backup without replacing an existing file: %w", errno)
	}
	if err := directory.Sync(); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), outputName)
		_ = directory.Sync()
		return fmt.Errorf("sync backup destination directory: %w", err)
	}
	return nil
}

func renameat2SyscallNumber() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return sysRenameat2AMD64, nil
	case "arm64":
		return sysRenameat2ARM64, nil
	default:
		return 0, fmt.Errorf("atomic no-replace backup publication is unsupported on linux/%s", runtime.GOARCH)
	}
}
