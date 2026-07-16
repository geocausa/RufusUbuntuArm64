package sourcefile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

const digestBufferSize = 4 * 1024 * 1024

// DigestProgress receives byte counts while a pinned source descriptor is
// hashed. It may be nil.
type DigestProgress func(done, total uint64)

// SHA256Open hashes an already-open regular file without reopening its path.
// The descriptor offset is restored before return so callers can safely use it
// for a later mount, copy, or verification pass.
func SHA256Open(ctx context.Context, file *os.File, progress DigestProgress) (result [sha256.Size]byte, returnErr error) {
	if file == nil {
		return result, errors.New("image file is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return result, fmt.Errorf("stat open image for hashing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return result, errors.New("image must be a non-empty regular file")
	}
	originalOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return result, fmt.Errorf("record image offset before hashing: %w", err)
	}
	defer func() {
		if _, err := file.Seek(originalOffset, io.SeekStart); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("restore image offset after hashing: %w", err)
		}
	}()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("seek image to start for hashing: %w", err)
	}

	hash := sha256.New()
	buffer := make([]byte, digestBufferSize)
	total := uint64(info.Size())
	var done uint64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			if _, err := hash.Write(buffer[:n]); err != nil {
				return result, fmt.Errorf("hash image: %w", err)
			}
			done += uint64(n)
			if progress != nil {
				progress(done, total)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, fmt.Errorf("read image for hashing: %w", readErr)
		}
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}
