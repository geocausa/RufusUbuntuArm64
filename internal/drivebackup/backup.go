package drivebackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"syscall"
)

const (
	ReportSchema      = 1
	defaultBufferSize = 4 * 1024 * 1024
	maxBufferSize     = 64 * 1024 * 1024
)

type Status string

const (
	StatusPassed    Status = "passed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

type Failure struct {
	Kind       string  `json:"kind"`
	Message    string  `json:"message"`
	ByteOffset *uint64 `json:"byte_offset,omitempty"`
}

type Report struct {
	Schema         int      `json:"schema"`
	Status         Status   `json:"status"`
	PlannedBytes   uint64   `json:"planned_bytes"`
	CompletedBytes uint64   `json:"completed_bytes"`
	SHA256         string   `json:"sha256,omitempty"`
	Failure        *Failure `json:"failure,omitempty"`
}

type Progress struct {
	Done  uint64 `json:"done"`
	Total uint64 `json:"total"`
}

type ProgressFunc func(Progress)

type Config struct {
	BufferSize int
	Progress   ProgressFunc
}

type syncWriter interface {
	io.Writer
	Sync() error
}

// Capture copies exactly size bytes from source into a newly created regular
// file. The destination is removed unless every byte is written, synced, and
// closed successfully.
func Capture(ctx context.Context, source io.ReaderAt, outputPath string, size uint64, config Config) (Report, error) {
	report, err := validate(ctx, source, outputPath, size, config)
	if err != nil {
		return report, err
	}

	output, err := os.OpenFile(
		outputPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fail(report, "open_destination", 0, false, fmt.Errorf("create backup destination: %w", err))
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(outputPath)
		}
	}()

	info, err := output.Stat()
	if err != nil {
		_ = output.Close()
		return fail(report, "inspect_destination", 0, false, fmt.Errorf("inspect backup destination: %w", err))
	}
	if !info.Mode().IsRegular() {
		_ = output.Close()
		return fail(report, "invalid_destination", 0, false, errors.New("backup destination is not a regular file"))
	}

	report, copyErr := Copy(ctx, source, output, size, config)
	closeErr := output.Close()
	if copyErr != nil {
		return report, copyErr
	}
	if closeErr != nil {
		return fail(report, "close_destination", report.CompletedBytes, true, fmt.Errorf("close backup destination: %w", closeErr))
	}
	keep = true
	return report, nil
}

// Copy runs the exact-size copy and verification accounting against an already
// opened destination. Capture should be preferred by callers that need cleanup
// and no-replace file creation.
func Copy(ctx context.Context, source io.ReaderAt, destination syncWriter, size uint64, config Config) (Report, error) {
	report, err := validateCopy(ctx, source, destination, size, config)
	if err != nil {
		return report, err
	}

	bufferSize := config.BufferSize
	if bufferSize == 0 {
		bufferSize = defaultBufferSize
	}
	buffer := make([]byte, bufferSize)
	hash := sha256.New()
	var offset uint64

	emit(config.Progress, 0, size)
	for offset < size {
		if err := ctx.Err(); err != nil {
			return cancel(report, offset, err)
		}
		remaining := size - offset
		chunkSize := uint64(len(buffer))
		if remaining < chunkSize {
			chunkSize = remaining
		}
		chunk := buffer[:int(chunkSize)]
		n, readErr := source.ReadAt(chunk, int64(offset))
		if n != len(chunk) {
			message := fmt.Errorf("read backup source at byte %d: %w", offset+uint64(n), io.ErrUnexpectedEOF)
			if readErr != nil {
				message = fmt.Errorf("read backup source at byte %d: %w", offset+uint64(n), readErr)
			}
			return fail(report, "source_read", offset+uint64(n), true, message)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fail(report, "source_read", offset+uint64(n), true, fmt.Errorf("read backup source at byte %d: %w", offset+uint64(n), readErr))
		}

		written := 0
		for written < len(chunk) {
			if err := ctx.Err(); err != nil {
				return cancel(report, offset+uint64(written), err)
			}
			n, writeErr := destination.Write(chunk[written:])
			if n < 0 || n > len(chunk)-written {
				return fail(report, "destination_write", offset+uint64(written), true, errors.New("backup destination returned an invalid write count"))
			}
			written += n
			if writeErr != nil {
				return fail(report, "destination_write", offset+uint64(written), true, fmt.Errorf("write backup destination at byte %d: %w", offset+uint64(written), writeErr))
			}
			if n == 0 {
				return fail(report, "destination_write", offset+uint64(written), true, fmt.Errorf("write backup destination at byte %d: %w", offset+uint64(written), io.ErrShortWrite))
			}
		}
		if _, err := hash.Write(chunk); err != nil {
			return fail(report, "hash", offset, true, fmt.Errorf("hash backup data: %w", err))
		}
		offset += chunkSize
		report.CompletedBytes = offset
		emit(config.Progress, offset, size)
	}

	if err := ctx.Err(); err != nil {
		return cancel(report, offset, err)
	}
	if err := destination.Sync(); err != nil {
		return fail(report, "sync_destination", offset, true, fmt.Errorf("sync backup destination: %w", err))
	}
	report.Status = StatusPassed
	report.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return report, nil
}

func validate(ctx context.Context, source io.ReaderAt, outputPath string, size uint64, config Config) (Report, error) {
	report, err := validateCommon(ctx, source, size, config)
	if err != nil {
		return report, err
	}
	if outputPath == "" {
		return fail(report, "invalid_destination", 0, false, errors.New("backup destination path is empty"))
	}
	return report, nil
}

func validateCopy(ctx context.Context, source io.ReaderAt, destination syncWriter, size uint64, config Config) (Report, error) {
	report, err := validateCommon(ctx, source, size, config)
	if err != nil {
		return report, err
	}
	if destination == nil {
		return fail(report, "invalid_destination", 0, false, errors.New("backup destination is nil"))
	}
	return report, nil
}

func validateCommon(ctx context.Context, source io.ReaderAt, size uint64, config Config) (Report, error) {
	report := Report{Schema: ReportSchema, Status: StatusFailed, PlannedBytes: size}
	if ctx == nil {
		return fail(report, "invalid_context", 0, false, errors.New("backup context is nil"))
	}
	if source == nil {
		return fail(report, "invalid_source", 0, false, errors.New("backup source is nil"))
	}
	if size == 0 {
		return fail(report, "invalid_size", 0, false, errors.New("backup size must be greater than zero"))
	}
	if size > math.MaxInt64 {
		return fail(report, "invalid_size", 0, false, errors.New("backup size exceeds the supported offset range"))
	}
	if config.BufferSize < 0 || config.BufferSize > maxBufferSize {
		return fail(report, "invalid_buffer", 0, false, fmt.Errorf("backup buffer size must be zero for the default or no more than %d bytes", maxBufferSize))
	}
	if err := ctx.Err(); err != nil {
		return cancel(report, 0, err)
	}
	return report, nil
}

func emit(progress ProgressFunc, done, total uint64) {
	if progress != nil {
		progress(Progress{Done: done, Total: total})
	}
}

func cancel(report Report, offset uint64, err error) (Report, error) {
	report.Status = StatusCancelled
	report.CompletedBytes = offset
	report.SHA256 = ""
	offsetCopy := offset
	report.Failure = &Failure{Kind: "cancelled", Message: err.Error(), ByteOffset: &offsetCopy}
	return report, err
}

func fail(report Report, kind string, offset uint64, includeOffset bool, err error) (Report, error) {
	report.Status = StatusFailed
	report.SHA256 = ""
	if offset > report.CompletedBytes {
		report.CompletedBytes = offset
	}
	failure := &Failure{Kind: kind, Message: err.Error()}
	if includeOffset {
		offsetCopy := offset
		failure.ByteOffset = &offsetCopy
	}
	report.Failure = failure
	return report, err
}
