package sourcefile

import (
	"context"
	"crypto/md5"  // #nosec G501 -- MD5 is exposed only for Rufus-compatible image checksums, not for trust decisions.
	"crypto/sha1" // #nosec G505 -- SHA-1 is exposed only for Rufus-compatible image checksums, not for trust decisions.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

const digestBufferSize = 4 * 1024 * 1024

// DigestAlgorithm identifies an image-checksum algorithm. MD5 and SHA-1 are
// retained solely for compatibility with checksum values published for older
// images; callers must not use them as trust or signature primitives.
type DigestAlgorithm string

const (
	DigestMD5    DigestAlgorithm = "md5"
	DigestSHA1   DigestAlgorithm = "sha1"
	DigestSHA256 DigestAlgorithm = "sha256"
	DigestSHA512 DigestAlgorithm = "sha512"
)

// DigestResult is one lowercase hexadecimal checksum from a descriptor-bound
// hashing pass.
type DigestResult struct {
	Algorithm DigestAlgorithm `json:"algorithm"`
	Hex       string          `json:"hex"`
}

// DigestProgress receives byte counts while a pinned source descriptor is
// hashed. It may be nil.
type DigestProgress func(done, total uint64)

type digestSink struct {
	algorithm DigestAlgorithm
	hash      hash.Hash
}

// ParseDigestAlgorithm accepts the spellings commonly used by checksum tools.
func ParseDigestAlgorithm(value string) (DigestAlgorithm, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "")
	switch normalized {
	case string(DigestMD5):
		return DigestMD5, nil
	case string(DigestSHA1):
		return DigestSHA1, nil
	case string(DigestSHA256):
		return DigestSHA256, nil
	case string(DigestSHA512):
		return DigestSHA512, nil
	default:
		return "", fmt.Errorf("unsupported digest algorithm %q", value)
	}
}

// SupportedDigestAlgorithms returns the complete stable checksum set in the
// same order Rufus presents it.
func SupportedDigestAlgorithms() []DigestAlgorithm {
	return []DigestAlgorithm{DigestMD5, DigestSHA1, DigestSHA256, DigestSHA512}
}

// DigestsOpen computes one or more checksums in a single pass over an already-
// open regular file. The descriptor offset is restored before return so callers
// can safely use the same pinned descriptor for a later inspection or write.
func DigestsOpen(ctx context.Context, file *os.File, algorithms []DigestAlgorithm, progress DigestProgress) ([]DigestResult, error) {
	sinks, err := prepareDigestSinks(algorithms)
	if err != nil {
		return nil, err
	}
	if err := hashOpen(ctx, file, sinks, progress); err != nil {
		return nil, err
	}
	results := make([]DigestResult, len(sinks))
	for index, sink := range sinks {
		results[index] = DigestResult{
			Algorithm: sink.algorithm,
			Hex:       hex.EncodeToString(sink.hash.Sum(nil)),
		}
	}
	return results, nil
}

// SHA256Open hashes an already-open regular file without reopening its path.
// It is retained as the safety-critical compatibility API used by writer and
// verification paths.
func SHA256Open(ctx context.Context, file *os.File, progress DigestProgress) (result [sha256.Size]byte, err error) {
	sinks, err := prepareDigestSinks([]DigestAlgorithm{DigestSHA256})
	if err != nil {
		return result, err
	}
	if err := hashOpen(ctx, file, sinks, progress); err != nil {
		return result, err
	}
	copy(result[:], sinks[0].hash.Sum(nil))
	return result, nil
}

func prepareDigestSinks(algorithms []DigestAlgorithm) ([]digestSink, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("at least one digest algorithm is required")
	}
	sinks := make([]digestSink, 0, len(algorithms))
	seen := make(map[DigestAlgorithm]struct{}, len(algorithms))
	for _, requested := range algorithms {
		algorithm, err := ParseDigestAlgorithm(string(requested))
		if err != nil {
			return nil, err
		}
		if _, exists := seen[algorithm]; exists {
			return nil, fmt.Errorf("duplicate digest algorithm %q", algorithm)
		}
		seen[algorithm] = struct{}{}
		sink, err := newDigestSink(algorithm)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

func newDigestSink(algorithm DigestAlgorithm) (digestSink, error) {
	switch algorithm {
	case DigestMD5:
		return digestSink{algorithm: algorithm, hash: md5.New()}, nil // #nosec G401 -- compatibility checksum only.
	case DigestSHA1:
		return digestSink{algorithm: algorithm, hash: sha1.New()}, nil // #nosec G401 -- compatibility checksum only.
	case DigestSHA256:
		return digestSink{algorithm: algorithm, hash: sha256.New()}, nil
	case DigestSHA512:
		return digestSink{algorithm: algorithm, hash: sha512.New()}, nil
	default:
		return digestSink{}, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
}

func hashOpen(ctx context.Context, file *os.File, sinks []digestSink, progress DigestProgress) (returnErr error) {
	if ctx == nil {
		return errors.New("hash context is nil")
	}
	if file == nil {
		return errors.New("image file is nil")
	}
	if len(sinks) == 0 {
		return errors.New("at least one digest sink is required")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open image for hashing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("image must be a non-empty regular file")
	}
	originalOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("record image offset before hashing: %w", err)
	}
	defer func() {
		if _, seekErr := file.Seek(originalOffset, io.SeekStart); seekErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("restore image offset after hashing: %w", seekErr)
		}
	}()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek image to start for hashing: %w", err)
	}

	buffer := make([]byte, digestBufferSize)
	total := uint64(info.Size())
	var done uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			for _, sink := range sinks {
				if _, err := sink.hash.Write(buffer[:n]); err != nil {
					return fmt.Errorf("hash image with %s: %w", sink.algorithm, err)
				}
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
			return fmt.Errorf("read image for hashing: %w", readErr)
		}
	}
	if done != total {
		return fmt.Errorf("image size changed while hashing: read %d bytes, expected %d", done, total)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open image after hashing: %w", err)
	}
	if after.Size() != info.Size() || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
		return errors.New("image metadata changed while hashing")
	}
	return nil
}
