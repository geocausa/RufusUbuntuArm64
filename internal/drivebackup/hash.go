package drivebackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
)

// HashExact computes SHA-256 over exactly size bytes from an already-held
// descriptor or other ReaderAt. It never changes a shared file offset and fails
// closed on truncation, expansion assumptions, cancellation, or read errors.
func HashExact(ctx context.Context, source io.ReaderAt, size uint64, phase string, progress ProgressFunc) (string, error) {
	if ctx == nil {
		return "", errors.New("hash context is nil")
	}
	if source == nil {
		return "", errors.New("hash source is nil")
	}
	if size == 0 {
		return "", errors.New("hash size must be greater than zero")
	}
	if size > math.MaxInt64 {
		return "", errors.New("hash size exceeds the supported offset range")
	}
	if err := ctx.Err(); err != nil {
		return "", context.Cause(ctx)
	}

	digest := sha256.New()
	buffer := make([]byte, defaultBufferSize)
	var offset uint64
	emitPhase(progress, phase, 0, size)
	for offset < size {
		if err := ctx.Err(); err != nil {
			return "", context.Cause(ctx)
		}
		remaining := size - offset
		chunkSize := uint64(len(buffer))
		if remaining < chunkSize {
			chunkSize = remaining
		}
		chunk := buffer[:int(chunkSize)]
		n, readErr := source.ReadAt(chunk, int64(offset))
		if n != len(chunk) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return "", fmt.Errorf("hash source at byte %d: %w", offset+uint64(n), readErr)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", fmt.Errorf("hash source at byte %d: %w", offset+uint64(n), readErr)
		}
		if _, err := digest.Write(chunk); err != nil {
			return "", fmt.Errorf("hash source at byte %d: %w", offset, err)
		}
		offset += chunkSize
		emitPhase(progress, phase, offset, size)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
