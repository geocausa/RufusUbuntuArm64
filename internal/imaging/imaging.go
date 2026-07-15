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
	"sync/atomic"
	"syscall"
	"time"
)

const DefaultBufferSize = 4 * 1024 * 1024

type Progress struct {
	Done        uint64
	Total       uint64
	BytesPerSec float64
	Elapsed     time.Duration
}

type ProgressFunc func(Progress)

type WriteOptions struct {
	BufferSize int
	Progress   ProgressFunc
}

func WriteImage(ctx context.Context, imagePath, devicePath string, opts WriteOptions) (uint64, error) {
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	src, err := os.Open(imagePath)
	if err != nil {
		return 0, fmt.Errorf("open image: %w", err)
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat image: %w", err)
	}
	total := uint64(info.Size())

	dst, err := os.OpenFile(devicePath, os.O_WRONLY|syscall.O_SYNC, 0)
	if err != nil {
		return 0, fmt.Errorf("open target device: %w", err)
	}
	defer dst.Close()
	if err := syscall.Flock(int(dst.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return 0, fmt.Errorf("acquire exclusive writer lock on target: %w", err)
	}
	defer syscall.Flock(int(dst.Fd()), syscall.LOCK_UN) // best-effort unlock on close

	var done atomic.Uint64
	started := time.Now()
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if opts.Progress != nil {
					elapsed := time.Since(started)
					n := done.Load()
					rate := 0.0
					if elapsed > 0 {
						rate = float64(n) / elapsed.Seconds()
					}
					opts.Progress(Progress{Done: n, Total: total, BytesPerSec: rate, Elapsed: elapsed})
				}
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
			close(stopProgress)
			<-progressDone
			return written, err
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			wn, writeErr := writeFull(dst, buf[:n])
			written += uint64(wn)
			done.Store(written)
			if writeErr != nil {
				close(stopProgress)
				<-progressDone
				return written, fmt.Errorf("write target at offset %d: %w", written-uint64(wn), writeErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			close(stopProgress)
			<-progressDone
			return written, fmt.Errorf("read image: %w", readErr)
		}
	}

	if err := dst.Sync(); err != nil {
		close(stopProgress)
		<-progressDone
		return written, fmt.Errorf("sync target: %w", err)
	}
	close(stopProgress)
	<-progressDone
	if opts.Progress != nil {
		elapsed := time.Since(started)
		rate := 0.0
		if elapsed > 0 {
			rate = float64(written) / elapsed.Seconds()
		}
		opts.Progress(Progress{Done: written, Total: total, BytesPerSec: rate, Elapsed: elapsed})
	}
	return written, nil
}

func VerifyImage(ctx context.Context, imagePath, devicePath string, progress ProgressFunc) (string, error) {
	src, err := os.Open(imagePath)
	if err != nil {
		return "", fmt.Errorf("open image: %w", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return "", fmt.Errorf("stat image: %w", err)
	}
	total := uint64(info.Size())

	dst, err := os.Open(devicePath)
	if err != nil {
		return "", fmt.Errorf("open target for verification: %w", err)
	}
	defer dst.Close()

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
		if progress != nil {
			elapsed := time.Since(started)
			rate := 0.0
			if elapsed > 0 {
				rate = float64(done) / elapsed.Seconds()
			}
			progress(Progress{Done: done, Total: total, BytesPerSec: rate, Elapsed: elapsed})
		}
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
