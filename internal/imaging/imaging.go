package imaging

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const (
	DefaultBufferSize       = 4 * 1024 * 1024
	staleSignatureClearSize = uint64(16 * 1024 * 1024)
)

type Progress struct {
	Done        uint64
	Total       uint64
	BytesPerSec float64
	Elapsed     time.Duration
}

type ProgressFunc func(Progress)

type WriteOptions struct {
	BufferSize       int
	Progress         ProgressFunc
	ExpectedDeviceID uint64
	ExpectedSource   sourcefile.Identity
	TargetSize       uint64
	// ClearStaleSignatures zeroes bounded regions at the beginning and end of
	// the already-open exclusive target before copying. This removes old GPT,
	// RAID, filesystem, and boot signatures without reopening the device path.
	ClearStaleSignatures bool
	// BeforeWrite runs after the target has been opened, identity-checked, and
	// exclusively locked, but before the first byte is changed. It is used for a
	// final mount and identity checks without reopening a race window.
	BeforeWrite func(source *os.File) error
}

func WriteImage(ctx context.Context, imagePath, devicePath string, opts WriteOptions) (uint64, error) {
	src, err := sourcefile.OpenRegular(imagePath, opts.ExpectedSource)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return WriteOpenImage(ctx, src, devicePath, opts)
}

// WriteOpenImage writes from an already-open source file. Keeping the source
// descriptor open across the final safety checks, signature wipe, write, and
// verification prevents path replacement from changing the selected image
// after the user confirms the destructive operation.
func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (uint64, error) {
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	if err := sourcefile.Verify(src, opts.ExpectedSource); err != nil {
		return 0, err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek image to start: %w", err)
	}
	info, err := src.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return 0, errors.New("image must be a non-empty regular file")
	}
	total := uint64(info.Size())
	if opts.TargetSize > 0 && total > opts.TargetSize {
		return 0, fmt.Errorf("image is %d bytes but target is only %d bytes", total, opts.TargetSize)
	}

	// Buffered writes followed by fsync are much faster than O_SYNC on USB flash,
	// while still giving a clear durability boundary before success is reported.
	dst, err := os.OpenFile(devicePath, os.O_WRONLY|syscall.O_EXCL, 0)
	if err != nil {
		return 0, fmt.Errorf("open target device: %w", err)
	}
	defer dst.Close()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return 0, err
	}
	if err := syscall.Flock(int(dst.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return 0, fmt.Errorf("acquire exclusive writer lock on target: %w", err)
	}
	defer syscall.Flock(int(dst.Fd()), syscall.LOCK_UN) // best effort

	if opts.BeforeWrite != nil {
		if err := opts.BeforeWrite(src); err != nil {
			return 0, fmt.Errorf("final target safety check: %w", err)
		}
	}
	// Re-check immediately before the first target write in case the source was
	// modified in place while administrator authentication was displayed.
	if err := sourcefile.Verify(src, opts.ExpectedSource); err != nil {
		return 0, err
	}
	if opts.ClearStaleSignatures {
		if opts.TargetSize == 0 {
			return 0, errors.New("target size is required when clearing stale signatures")
		}
		if err := clearTargetEdges(ctx, dst, opts.TargetSize); err != nil {
			return 0, fmt.Errorf("clear stale target signatures: %w", err)
		}
	}

	var done atomic.Uint64
	started := time.Now()
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	var stopOnce sync.Once
	stopReporter := func() {
		stopOnce.Do(func() { close(stopProgress) })
		<-progressDone
	}
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				emitProgress(opts.Progress, done.Load(), total, started)
			case <-stopProgress:
				return
			}
		}
	}()

	reader := bufio.NewReaderSize(src, opts.BufferSize)
	buf := make([]byte, opts.BufferSize)
	var written uint64
	for {
		if err := ctx.Err(); err != nil {
			syncErr := dst.Sync()
			stopReporter()
			if syncErr != nil {
				return written, fmt.Errorf("operation cancelled; flushing partial write also failed: %w", syncErr)
			}
			return written, err
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			wn, writeErr := writeFull(dst, buf[:n])
			written += uint64(wn)
			done.Store(written)
			if writeErr != nil {
				syncErr := dst.Sync()
				stopReporter()
				if syncErr != nil {
					return written, fmt.Errorf("write target at offset %d: %v; flushing partial write: %w", written-uint64(wn), writeErr, syncErr)
				}
				return written, fmt.Errorf("write target at offset %d: %w", written-uint64(wn), writeErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			syncErr := dst.Sync()
			stopReporter()
			if syncErr != nil {
				return written, fmt.Errorf("read image: %v; flushing partial write: %w", readErr, syncErr)
			}
			return written, fmt.Errorf("read image: %w", readErr)
		}
	}

	if err := dst.Sync(); err != nil {
		stopReporter()
		return written, fmt.Errorf("sync target: %w", err)
	}
	stopReporter()
	// Detect in-place changes that occurred during the copy. The USB has already
	// been changed at this point, but reporting failure is safer than claiming a
	// coherent image was written from a moving source.
	if err := sourcefile.Verify(src, opts.ExpectedSource); err != nil {
		return written, err
	}
	emitProgress(opts.Progress, written, total, started)
	return written, nil
}

type VerifyOptions struct {
	ExpectedDeviceID   uint64
	ExpectedDeviceSize uint64
	ExpectedSource     sourcefile.Identity
}

func VerifyImage(ctx context.Context, imagePath, devicePath string, progress ProgressFunc) (string, error) {
	return VerifyImageWithOptions(ctx, imagePath, devicePath, VerifyOptions{}, progress)
}

func VerifyImageWithOptions(ctx context.Context, imagePath, devicePath string, opts VerifyOptions, progress ProgressFunc) (string, error) {
	src, err := sourcefile.OpenRegular(imagePath, opts.ExpectedSource)
	if err != nil {
		return "", err
	}
	defer src.Close()
	return VerifyOpenImageWithOptions(ctx, src, devicePath, opts, progress)
}

// VerifyOpenImageWithOptions compares the selected image, held by an open file
// descriptor, with the target. It is the verification counterpart to
// WriteOpenImage and closes the source path-replacement race completely.
func VerifyOpenImageWithOptions(ctx context.Context, src *os.File, devicePath string, opts VerifyOptions, progress ProgressFunc) (string, error) {
	if err := sourcefile.Verify(src, opts.ExpectedSource); err != nil {
		return "", err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek image to start for verification: %w", err)
	}
	info, err := src.Stat()
	if err != nil {
		return "", fmt.Errorf("stat image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", errors.New("image must be a non-empty regular file")
	}
	total := uint64(info.Size())

	dst, err := os.Open(devicePath)
	if err != nil {
		return "", fmt.Errorf("open target for verification: %w", err)
	}
	defer dst.Close()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
		return "", err
	}

	imageHash := sha256.New()
	deviceHash := sha256.New()
	srcBuf := make([]byte, DefaultBufferSize)
	dstBuf := make([]byte, DefaultBufferSize)
	var done uint64
	started := time.Now()

	for done < total {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := total - done
		chunk := len(srcBuf)
		if uint64(chunk) > remaining {
			chunk = int(remaining)
		}
		if _, err := io.ReadFull(src, srcBuf[:chunk]); err != nil {
			return "", fmt.Errorf("read image during verification: %w", err)
		}
		if _, err := io.ReadFull(dst, dstBuf[:chunk]); err != nil {
			return "", fmt.Errorf("read target during verification: %w", err)
		}
		if !equalBytes(srcBuf[:chunk], dstBuf[:chunk]) {
			return "", fmt.Errorf("verification mismatch at or before offset %d", done+uint64(chunk))
		}
		_, _ = imageHash.Write(srcBuf[:chunk])
		_, _ = deviceHash.Write(dstBuf[:chunk])
		done += uint64(chunk)
		emitProgress(progress, done, total, started)
	}

	if err := sourcefile.Verify(src, opts.ExpectedSource); err != nil {
		return "", err
	}
	left := imageHash.Sum(nil)
	right := deviceHash.Sum(nil)
	if !equalBytes(left, right) {
		return "", errors.New("verification hashes differ")
	}
	return hex.EncodeToString(left), nil
}

func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, DefaultBufferSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func clearTargetEdges(ctx context.Context, target *os.File, targetSize uint64) error {
	if target == nil {
		return errors.New("target file is nil")
	}
	if targetSize == 0 {
		return errors.New("target size is zero")
	}
	if targetSize > uint64(^uint64(0)>>1) {
		return errors.New("target is too large for this platform")
	}
	clearSize := staleSignatureClearSize
	if targetSize <= 2*clearSize {
		if err := writeZerosAt(ctx, target, 0, targetSize); err != nil {
			return err
		}
		return target.Sync()
	}
	if err := writeZerosAt(ctx, target, 0, clearSize); err != nil {
		return err
	}
	if err := writeZerosAt(ctx, target, targetSize-clearSize, clearSize); err != nil {
		return err
	}
	return target.Sync()
}

func writeZerosAt(ctx context.Context, target *os.File, offset, length uint64) error {
	zeroes := make([]byte, 1024*1024)
	for written := uint64(0); written < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := uint64(len(zeroes))
		if remaining := length - written; chunk > remaining {
			chunk = remaining
		}
		n, err := target.WriteAt(zeroes[:int(chunk)], int64(offset+written))
		written += uint64(n)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func emitProgress(progress ProgressFunc, done, total uint64, started time.Time) {
	if progress == nil {
		return
	}
	elapsed := time.Since(started)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(done) / elapsed.Seconds()
	}
	progress(Progress{Done: done, Total: total, BytesPerSec: rate, Elapsed: elapsed})
}

func writeFull(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
