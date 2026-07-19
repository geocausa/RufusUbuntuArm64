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
	atFDCWD               = ^uintptr(99)
	renameNoReplace       = 1
	sysRenameat2AMD64     = 316
	sysRenameat2ARM64     = 276
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

	cleanOutput, destinationDir, err := prepareDestination(outputPath, sourcePath, options.ExpectedSize)
	if err != nil {
		return fail(report, "destination_preflight", 0, false, err)
	}

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

	temporary, err := os.CreateTemp(destinationDir, "."+filepath.Base(cleanOutput)+".rufusarm64-partial-*")
	if err != nil {
		return fail(report, "open_destination", 0, false, fmt.Errorf("create backup temporary destination: %w", err))
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return fail(report, "inspect_destination", 0, false, fmt.Errorf("inspect backup temporary destination: %w", err))
	}
	if !info.Mode().IsRegular() {
		_ = temporary.Close()
		return fail(report, "invalid_destination", 0, false, errors.New("backup temporary destination is not a regular file"))
	}
	if info.Mode().Perm() != 0o600 {
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			return fail(report, "secure_destination", 0, false, fmt.Errorf("secure backup temporary destination: %w", err))
		}
	}

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
	if err := publishNoReplace(temporaryPath, cleanOutput); err != nil {
		return fail(report, "publish_destination", report.CompletedBytes, true, err)
	}
	return report, nil
}

func prepareDestination(outputPath, sourcePath string, required uint64) (string, string, error) {
	if outputPath == "" {
		return "", "", errors.New("backup destination path is empty")
	}
	clean := filepath.Clean(outputPath)
	if !filepath.IsAbs(clean) {
		return "", "", errors.New("backup destination path must be absolute")
	}
	if clean == string(filepath.Separator) || filepath.Base(clean) == "." {
		return "", "", errors.New("backup destination must name a file")
	}
	if _, err := os.Lstat(clean); err == nil {
		return "", "", fmt.Errorf("backup destination already exists: %s", clean)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect backup destination: %w", err)
	}
	directory := filepath.Dir(clean)
	info, err := os.Stat(directory)
	if err != nil {
		return "", "", fmt.Errorf("inspect backup destination directory: %w", err)
	}
	if !info.IsDir() {
		return "", "", errors.New("backup destination parent is not a directory")
	}
	if err := safety.EnsurePathNotOnTarget(directory, sourcePath); err != nil {
		return "", "", fmt.Errorf("validate backup destination storage: %w", err)
	}
	if err := ensureFreeSpace(directory, required); err != nil {
		return "", "", err
	}
	return clean, directory, nil
}

func ensureFreeSpace(path string, required uint64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
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

func publishNoReplace(temporaryPath, outputPath string) error {
	syscallNumber, err := renameat2SyscallNumber()
	if err != nil {
		return err
	}
	temporaryPointer, err := syscall.BytePtrFromString(temporaryPath)
	if err != nil {
		return fmt.Errorf("encode backup temporary path: %w", err)
	}
	outputPointer, err := syscall.BytePtrFromString(outputPath)
	if err != nil {
		return fmt.Errorf("encode backup destination path: %w", err)
	}
	_, _, errno := syscall.Syscall6(
		syscallNumber,
		atFDCWD,
		uintptr(unsafe.Pointer(temporaryPointer)),
		atFDCWD,
		uintptr(unsafe.Pointer(outputPointer)),
		renameNoReplace,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("publish backup without replacing an existing file: %w", errno)
	}
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		_ = os.Remove(outputPath)
		_ = syncDirectory(filepath.Dir(outputPath))
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

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
