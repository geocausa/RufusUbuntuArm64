package imaging

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

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

type SourceHoldStatus struct {
	Held     bool
	Fallback bool
	Message  string
}

type WriteOptions struct {
	BufferSize int
	Progress   ProgressFunc
	// SnapshotProgress reports the non-destructive source hashing pass that
	// binds the bytes consumed by the later destructive write.
	SnapshotProgress ProgressFunc
	ExpectedDeviceID uint64
	ExpectedSource   sourcefile.Identity
	TargetSize       uint64
	// ClearStaleSignatures zeroes bounded regions at the beginning and end of
	// the already-open exclusive target before copying. This removes old GPT,
	// RAID, filesystem, and boot signatures without reopening the device path.
	ClearStaleSignatures bool
	HoldSource           bool
	SourceHold           func(SourceHoldStatus)
	// BeforeWrite runs after the target has been opened, identity-checked, and
	// exclusively locked, but before the first byte is changed. It is used for a
	// final mount and identity checks without reopening a race window.
	BeforeWrite func(source *os.File) error

	trustedSnapshot         [sha256.Size]byte
	trustedSnapshotSet      bool
	trustedSnapshotIdentity sourcefile.Identity
	beforeMutation          func()
	afterWriteChunk         func(uint64)
}

func WriteImage(ctx context.Context, imagePath, devicePath string, opts WriteOptions) (uint64, error) {
	src, err := sourcefile.OpenRegular(imagePath, opts.ExpectedSource)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return WriteOpenImage(ctx, src, devicePath, opts)
}

// WriteResult records the exact byte count and SHA-256 authenticated by a completed image write.
type WriteResult struct {
	BytesWritten uint64
	SHA256       string
}

// WriteOpenImage writes from an already-open source file. Keeping the source
// descriptor open across the final safety checks, signature wipe, write, and
// verification prevents path replacement from changing the selected image
// after the user confirms the destructive operation.
func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (uint64, error) {
	result, err := writeOpenImage(ctx, src, devicePath, opts)
	return result.BytesWritten, err
}

func WriteOpenImageWithResult(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
	return writeOpenImage(ctx, src, devicePath, opts)
}

// WritePreparedOpenImageWithResult accepts the package-owned digest bound while
// materializing a private prepared.raw file. Caller-created PreparedInput values
// cannot set the unexported digest and therefore remain on the normal prehash path.
func WritePreparedOpenImageWithResult(ctx context.Context, prepared *PreparedInput, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
	if prepared == nil {
		return WriteResult{}, errors.New("prepared image is nil")
	}
	if src == nil {
		return WriteResult{}, errors.New("prepared image source is nil")
	}
	actual, err := sourcefile.IdentityOf(src)
	if err != nil {
		return WriteResult{}, err
	}
	if actual != prepared.Identity {
		return WriteResult{}, errors.New("opened prepared image does not match its package-owned identity")
	}
	if opts.ExpectedSource != (sourcefile.Identity{}) && opts.ExpectedSource != prepared.Identity {
		return WriteResult{}, errors.New("prepared image identity does not match the writer plan")
	}
	opts.ExpectedSource = prepared.Identity
	if prepared.rawSHA256Bound {
		if !prepared.Temporary || prepared.tempDir == "" || filepath.Clean(filepath.Dir(prepared.Path)) != filepath.Clean(prepared.tempDir) {
			return WriteResult{}, errors.New("prepared image digest is not bound to a private package-owned materialization")
		}
		opts.trustedSnapshot = prepared.rawSHA256
		opts.trustedSnapshotSet = true
		opts.trustedSnapshotIdentity = prepared.Identity
	}
	return writeOpenImage(ctx, src, devicePath, opts)
}

func writeOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (writeResult WriteResult, resultErr error) {
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	var sourceLease *sourcefile.ReadLease
	targetChanged := false
	if opts.HoldSource {
		lease, leaseErr := sourcefile.AcquireReadLease(ctx, src, opts.ExpectedSource)
		switch {
		case leaseErr == nil:
			sourceLease = lease
			ctx = lease.Context()
			if opts.SourceHold != nil {
				opts.SourceHold(SourceHoldStatus{Held: true, Message: "Holding the selected raw image read-only with a Linux kernel lease during destructive writing."})
			}
			defer func() {
				heldErr := sourceLease.Check()
				if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
					message := "the selected raw image was opened for writing before target mutation; nothing was erased"
					if targetChanged {
						message = "the selected raw image was opened for writing during the destructive write; the USB is incomplete and must be recreated"
					}
					heldErr = fmt.Errorf("%s: %w", message, heldErr)
				}
				closeErr := sourceLease.Close()
				resultErr = errors.Join(resultErr, heldErr, closeErr)
			}()
		case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
			if opts.SourceHold != nil {
				opts.SourceHold(SourceHoldStatus{Fallback: true, Message: fmt.Sprintf("Kernel raw-source hold unavailable (%v); retaining conservative pre-write and write-time digest comparison.", leaseErr)})
			}
		default:
			return writeResult, fmt.Errorf("hold selected raw image stable: %w", leaseErr)
		}
	}
	if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
		return writeResult, err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return writeResult, fmt.Errorf("seek image to start: %w", err)
	}
	info, err := src.Stat()
	if err != nil {
		return writeResult, fmt.Errorf("stat image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return writeResult, errors.New("image must be a non-empty regular file")
	}
	total := uint64(info.Size())
	if opts.TargetSize > 0 && total > opts.TargetSize {
		return writeResult, fmt.Errorf("image is %d bytes but target is only %d bytes", total, opts.TargetSize)
	}

	// Ordinary sources are hashed before the target is opened. A package-owned
	// prepared.raw may supply the digest computed while it was privately
	// materialized, avoiding a redundant read without exposing a caller-controlled
	// digest bypass.
	var snapshotHash [sha256.Size]byte
	if opts.trustedSnapshotSet {
		if err := sourcefile.Verify(src, opts.trustedSnapshotIdentity); err != nil {
			return writeResult, err
		}
		snapshotHash = opts.trustedSnapshot
	} else {
		snapshotTracker := newRateTracker()
		snapshotHash, err = sourcefile.SHA256Open(ctx, src, func(done, total uint64) {
			emitProgress(opts.SnapshotProgress, snapshotTracker, done, total)
		})
		if err != nil {
			return writeResult, fmt.Errorf("hash selected image before writing: %w", err)
		}
		if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
			return writeResult, err
		}
	}

	// Buffered writes followed by fsync are much faster than O_SYNC on USB flash,
	// while still giving a clear durability boundary before success is reported.
	dst, err := os.OpenFile(devicePath, os.O_WRONLY|syscall.O_EXCL, 0)
	if err != nil {
		return writeResult, fmt.Errorf("open target device: %w", err)
	}
	locked := false
	defer func() {
		resultErr = finishWriteTarget(resultErr, dst, locked)
	}()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return writeResult, err
	}
	if err := syscall.Flock(int(dst.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return writeResult, fmt.Errorf("acquire exclusive writer lock on target: %w", err)
	}
	locked = true

	if opts.BeforeWrite != nil {
		if err := opts.BeforeWrite(src); err != nil {
			return writeResult, fmt.Errorf("final target safety check: %w", err)
		}
	}
	// Re-check immediately before the first target write in case the source was
	// modified in place while administrator authentication was displayed.
	if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
		return writeResult, err
	}
	if opts.beforeMutation != nil {
		opts.beforeMutation()
	}
	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return writeResult, err
		}
	}
	if err := ctx.Err(); err != nil {
		return writeResult, context.Cause(ctx)
	}
	if opts.ClearStaleSignatures {
		targetChanged = true
		if opts.TargetSize == 0 {
			return writeResult, errors.New("target size is required when clearing stale signatures")
		}
		if err := clearTargetEdges(ctx, dst, opts.TargetSize); err != nil {
			return writeResult, fmt.Errorf("clear stale target signatures: %w", err)
		}
	}

	var done atomic.Uint64
	tracker := newRateTracker()
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
				emitProgress(opts.Progress, tracker, done.Load(), total)
			case <-stopProgress:
				return
			}
		}
	}()

	reader := bufio.NewReaderSize(src, opts.BufferSize)
	buf := make([]byte, opts.BufferSize)
	writtenHash := sha256.New()
	var written uint64
	for {
		if err := ctx.Err(); err != nil {
			syncErr := dst.Sync()
			stopReporter()
			if syncErr != nil {
				return WriteResult{BytesWritten: written}, fmt.Errorf("operation cancelled; flushing partial write also failed: %w", syncErr)
			}
			return WriteResult{BytesWritten: written}, err
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			_, _ = writtenHash.Write(buf[:n])
			wn, writeErr := writeFull(dst, buf[:n])
			if wn > 0 {
				targetChanged = true
			}
			written += uint64(wn)
			if wn > 0 && opts.afterWriteChunk != nil {
				opts.afterWriteChunk(written)
			}
			done.Store(written)
			if writeErr != nil {
				syncErr := dst.Sync()
				stopReporter()
				if syncErr != nil {
					return WriteResult{BytesWritten: written}, fmt.Errorf("write target at offset %d: %v; flushing partial write: %w", written-uint64(wn), writeErr, syncErr)
				}
				return WriteResult{BytesWritten: written}, fmt.Errorf("write target at offset %d: %w", written-uint64(wn), writeErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			syncErr := dst.Sync()
			stopReporter()
			if syncErr != nil {
				return WriteResult{BytesWritten: written}, fmt.Errorf("read image: %v; flushing partial write: %w", readErr, syncErr)
			}
			return WriteResult{BytesWritten: written}, fmt.Errorf("read image: %w", readErr)
		}
	}

	if err := dst.Sync(); err != nil {
		stopReporter()
		return WriteResult{BytesWritten: written}, fmt.Errorf("sync target: %w", err)
	}
	stopReporter()
	// Detect in-place changes that occurred during the copy. The USB has already
	// been changed at this point, but reporting failure is safer than claiming a
	// coherent image was written from a moving source.
	if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
		return WriteResult{BytesWritten: written}, err
	}
	if !bytes.Equal(snapshotHash[:], writtenHash.Sum(nil)) {
		return WriteResult{BytesWritten: written}, errors.New("the selected image changed while it was being written; the USB is incomplete and must be recreated")
	}
	emitProgress(opts.Progress, tracker, written, total)
	return WriteResult{BytesWritten: written, SHA256: hex.EncodeToString(snapshotHash[:])}, nil
}

type VerifyOptions struct {
	ExpectedDeviceID   uint64
	ExpectedDeviceSize uint64
	ExpectedSource     sourcefile.Identity
}

type DigestVerifyOptions struct {
	ExpectedDeviceID   uint64
	ExpectedDeviceSize uint64
	ImageSize          uint64
	ExpectedSHA256     string
}

// VerifyTargetDigestWithOptions reads only the physical target prefix and
// compares it with the SHA-256 authenticated by the completed write. It avoids
// rereading an unchanged source solely to recompute the same digest.
func VerifyTargetDigestWithOptions(ctx context.Context, devicePath string, opts DigestVerifyOptions, progress ProgressFunc) (string, error) {
	if opts.ImageSize == 0 {
		return "", errors.New("verification image size is zero")
	}
	if opts.ExpectedDeviceSize > 0 && opts.ImageSize > opts.ExpectedDeviceSize {
		return "", errors.New("verification image size exceeds the selected target")
	}
	expected, err := hex.DecodeString(strings.TrimSpace(opts.ExpectedSHA256))
	if err != nil || len(expected) != sha256.Size {
		return "", errors.New("verification requires a valid authenticated SHA-256 digest")
	}

	dst, sectorSize, direct, err := openForVerification(devicePath)
	if err != nil {
		return "", fmt.Errorf("open target for verification: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
		return "", err
	}

	alignment := directIOAlignment
	if sectorSize > alignment {
		alignment = sectorSize
	}
	dstBuf := alignedBuffer(DefaultBufferSize, alignment)
	deviceHash := sha256.New()
	var done uint64
	tracker := newRateTracker()
	lastEmit := time.Time{}

	for done < opts.ImageSize {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := opts.ImageSize - done
		chunk := len(dstBuf)
		if uint64(chunk) > remaining {
			chunk = int(remaining)
		}
		deviceChunk := chunk
		if direct {
			deviceChunk = roundUp(chunk, sectorSize)
		}
		if _, readErr := io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
			if direct && directIOUnsupported(readErr) {
				_ = dst.Close()
				dst, err = os.Open(devicePath)
				if err != nil {
					return "", fmt.Errorf("reopen target after O_DIRECT refusal: %w", err)
				}
				if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
					return "", err
				}
				if _, err := dst.Seek(int64(done), io.SeekStart); err != nil {
					return "", fmt.Errorf("seek buffered verification target: %w", err)
				}
				direct = false
				sectorSize = 1
				deviceChunk = chunk
				if _, readErr = io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
					return "", fmt.Errorf("read target during buffered verification: %w", readErr)
				}
			} else {
				return "", fmt.Errorf("read target during verification: %w", readErr)
			}
		}
		_, _ = deviceHash.Write(dstBuf[:chunk])
		done += uint64(chunk)
		if now := time.Now(); done == opts.ImageSize || now.Sub(lastEmit) >= 200*time.Millisecond {
			lastEmit = now
			emitProgress(progress, tracker, done, opts.ImageSize)
		}
	}

	actual := deviceHash.Sum(nil)
	if !bytes.Equal(expected, actual) {
		return "", errors.New("verification SHA-256 mismatch; the USB does not match the authenticated image bytes")
	}
	return hex.EncodeToString(actual), nil
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
	if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
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

	dst, sectorSize, direct, err := openForVerification(devicePath)
	if err != nil {
		return "", fmt.Errorf("open target for verification: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
		return "", err
	}

	imageHash := sha256.New()
	deviceHash := sha256.New()
	srcBuf := make([]byte, DefaultBufferSize)
	alignment := directIOAlignment
	if sectorSize > alignment {
		alignment = sectorSize
	}
	dstBuf := alignedBuffer(DefaultBufferSize, alignment)
	var done uint64
	tracker := newRateTracker()
	lastEmit := time.Time{}

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
		deviceChunk := chunk
		if direct {
			// O_DIRECT reads must be a multiple of the logical sector size.
			// The device is at least as large as the image and its capacity
			// is a multiple of its sector size, so the padded final read
			// stays within the device.
			deviceChunk = roundUp(chunk, sectorSize)
		}
		if _, readErr := io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
			if direct && directIOUnsupported(readErr) {
				// Some USB bridges accept O_DIRECT at open time but reject the
				// first aligned read. Fall back only for an explicit unsupported
				// error, revalidate the newly opened descriptor, and resume at the
				// exact byte offset already checked.
				_ = dst.Close()
				dst, err = os.Open(devicePath)
				if err != nil {
					return "", fmt.Errorf("reopen target after O_DIRECT refusal: %w", err)
				}
				if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
					return "", err
				}
				if _, err := dst.Seek(int64(done), io.SeekStart); err != nil {
					return "", fmt.Errorf("seek buffered verification target: %w", err)
				}
				direct = false
				sectorSize = 1
				deviceChunk = chunk
				if _, readErr = io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
					return "", fmt.Errorf("read target during buffered verification: %w", readErr)
				}
			} else {
				return "", fmt.Errorf("read target during verification: %w", readErr)
			}
		}
		if !bytes.Equal(srcBuf[:chunk], dstBuf[:chunk]) {
			return "", fmt.Errorf("verification mismatch at or before offset %d", done+uint64(chunk))
		}
		_, _ = imageHash.Write(srcBuf[:chunk])
		_, _ = deviceHash.Write(dstBuf[:chunk])
		done += uint64(chunk)
		if now := time.Now(); done == total || now.Sub(lastEmit) >= 200*time.Millisecond {
			lastEmit = now
			emitProgress(progress, tracker, done, total)
		}
	}

	if err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
		return "", err
	}
	left := imageHash.Sum(nil)
	right := deviceHash.Sum(nil)
	if !bytes.Equal(left, right) {
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

// rateTracker reports a recent transfer rate instead of a whole-operation
// average. USB flash write speed commonly collapses after the drive's cache
// fills; an exponentially weighted rate over the last few samples tracks the
// real speed the user is currently seeing instead of lagging behind it.
type rateTracker struct {
	started  time.Time
	lastTime time.Time
	lastDone uint64
	rate     float64
	primed   bool
}

func newRateTracker() *rateTracker {
	now := time.Now()
	return &rateTracker{started: now, lastTime: now}
}

func (r *rateTracker) sample(done uint64) (float64, time.Duration) {
	now := time.Now()
	interval := now.Sub(r.lastTime)
	if interval > 0 && done >= r.lastDone {
		instant := float64(done-r.lastDone) / interval.Seconds()
		if !r.primed {
			r.rate = instant
			r.primed = true
		} else {
			// Smooth over roughly the last three seconds of samples.
			alpha := interval.Seconds() / 3.0
			if alpha > 1 {
				alpha = 1
			}
			r.rate += alpha * (instant - r.rate)
		}
		r.lastTime = now
		r.lastDone = done
	}
	return r.rate, now.Sub(r.started)
}

func emitProgress(progress ProgressFunc, tracker *rateTracker, done, total uint64) {
	if progress == nil {
		return
	}
	rate, elapsed := tracker.sample(done)
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

const directIOAlignment = 4096

// openForVerification opens the target so verification reads come from the
// physical medium rather than the page cache. For block devices it retries
// with O_DIRECT, which bypasses the cache entirely; "blockdev --flushbufs"
// invalidation alone is advisory and pages can be repopulated between the
// flush and the read. Regular files (used by tests) and devices that refuse
// O_DIRECT fall back to a normal buffered descriptor.
func openForVerification(path string) (*os.File, int, bool, error) {
	plain, err := os.Open(path)
	if err != nil {
		return nil, 0, false, err
	}
	info, err := plain.Stat()
	if err != nil {
		plain.Close()
		return nil, 0, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return plain, 1, false, nil
	}
	sectorSize, err := logicalSectorSizeOf(plain)
	if err != nil || sectorSize <= 0 || DefaultBufferSize%sectorSize != 0 {
		return plain, 1, false, nil
	}
	direct, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		return plain, 1, false, nil
	}
	plain.Close()
	return direct, sectorSize, true, nil
}

// blkSSZGet is the BLKSSZGET ioctl request: the logical sector size in bytes.
const blkSSZGet = 0x1268

func logicalSectorSizeOf(file *os.File) (int, error) {
	var size int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blkSSZGet, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, errno
	}
	return int(size), nil
}

// alignedBuffer returns a buffer whose base address is aligned for O_DIRECT.
func alignedBuffer(size, align int) []byte {
	raw := make([]byte, size+align)
	offset := int(uintptr(unsafe.Pointer(&raw[0])) % uintptr(align))
	if offset != 0 {
		offset = align - offset
	}
	return raw[offset : offset+size]
}

func roundUp(value, multiple int) int {
	if multiple <= 1 {
		return value
	}
	remainder := value % multiple
	if remainder == 0 {
		return value
	}
	return value + multiple - remainder
}

func directIOUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP)
}
