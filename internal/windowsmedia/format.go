//go:build linux

package windowsmedia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const zeroBufferSize = 4 * 1024 * 1024

// zeroPartition performs the non-quick-format pass through the newly created
// partition. The whole-disk descriptor remains locked by Create while this
// child node is open, and every loop observes cancellation.
func zeroPartition(ctx context.Context, partitionPath string, size uint64, emit EventFunc) (returnErr error) {
	if size == 0 {
		return fmt.Errorf("cannot fully format a zero-length partition")
	}
	partition, err := os.OpenFile(partitionPath, os.O_WRONLY|os.O_EXCL, 0)
	if err != nil {
		return fmt.Errorf("open partition for full format: %w", err)
	}
	defer func() {
		if err := partition.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close partition after full format: %w", err)
		}
	}()

	buffer := make([]byte, zeroBufferSize)
	var written uint64
	lastEmit := time.Time{}
	send(emit, Event{Stage: "format", Message: "Performing a full zero-write format pass…", Total: size})
	for written < size {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		remaining := size - written
		chunk := uint64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		n, err := partition.Write(buffer[:int(chunk)])
		if err != nil {
			return fmt.Errorf("full-format write at %s: %w", humanBytes(written), err)
		}
		if n == 0 {
			return fmt.Errorf("full-format write made no progress at %s", humanBytes(written))
		}
		written += uint64(n)
		if now := time.Now(); written == size || now.Sub(lastEmit) >= 200*time.Millisecond {
			lastEmit = now
			send(emit, Event{Stage: "format", Message: "Performing a full zero-write format pass…", Done: written, Total: size})
		}
	}
	if err := partition.Sync(); err != nil {
		return fmt.Errorf("flush full-format writes: %w", err)
	}
	return nil
}

// verifyZeroPartition reads back the non-quick-format pass. This is a single
// destructive media-check pass, comparable to Rufus's one-pass bad-block
// option but deliberately limited to a zero pattern so the implementation is
// auditable and cancellation-safe.
func verifyZeroPartition(ctx context.Context, partitionPath string, size uint64, emit EventFunc) (returnErr error) {
	if size == 0 {
		return fmt.Errorf("cannot verify a zero-length partition")
	}
	// Bad-block detection is meaningless if reads are satisfied by the page
	// cache that the zero pass just filled, so block devices are read with
	// O_DIRECT. Regular files (used by tests) fall back to buffered reads.
	partition, sectorSize, direct, err := openPartitionForReadback(partitionPath)
	if err != nil {
		return fmt.Errorf("open partition for bad-block verification: %w", err)
	}
	defer func() {
		if err := partition.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close partition after bad-block verification: %w", err)
		}
	}()

	alignment := 4096
	if sectorSize > alignment {
		alignment = sectorSize
	}
	buffer := alignedReadBuffer(zeroBufferSize, alignment)
	zeros := make([]byte, zeroBufferSize)
	var checked uint64
	lastEmit := time.Time{}
	send(emit, Event{Stage: "badblocks", Message: "Reading back the full partition to check the USB…", Total: size})
	for checked < size {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		remaining := size - checked
		chunk := uint64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		readChunk := int(chunk)
		if direct && readChunk%sectorSize != 0 {
			readChunk = roundUpInt(readChunk, sectorSize)
		}
		n, readErr := io.ReadFull(partition, buffer[:readChunk])
		if readErr != nil {
			if direct && directReadUnsupported(readErr) {
				_ = partition.Close()
				partition, err = os.Open(partitionPath)
				if err != nil {
					return fmt.Errorf("reopen partition after O_DIRECT refusal: %w", err)
				}
				if _, err := partition.Seek(int64(checked), io.SeekStart); err != nil {
					return fmt.Errorf("seek buffered bad-block reader: %w", err)
				}
				direct = false
				sectorSize = 1
				n, readErr = io.ReadFull(partition, buffer[:int(chunk)])
				if readErr != nil {
					return fmt.Errorf("buffered bad-block verification read at %s: %w", humanBytes(checked), readErr)
				}
			} else {
				return fmt.Errorf("bad-block verification read at %s: %w", humanBytes(checked), readErr)
			}
		}
		compareN := int(chunk)
		if n < compareN {
			return fmt.Errorf("short bad-block verification read at %s: got %d of %d bytes", humanBytes(checked), n, compareN)
		}
		if !bytes.Equal(buffer[:compareN], zeros[:compareN]) {
			for index, value := range buffer[:compareN] {
				if value != 0 {
					return fmt.Errorf("USB media verification failed at byte %d: expected zero, read 0x%02x", checked+uint64(index), value)
				}
			}
		}
		checked += uint64(n)
		if now := time.Now(); checked == size || now.Sub(lastEmit) >= 200*time.Millisecond {
			lastEmit = now
			send(emit, Event{Stage: "badblocks", Message: "Reading back the full partition to check the USB…", Done: checked, Total: size})
		}
	}
	return nil
}

// openPartitionForReadback opens a block device with O_DIRECT so readback
// verification exercises the physical medium. Anything that refuses O_DIRECT,
// including the regular files used by tests, is read through a normal
// buffered descriptor instead.
func openPartitionForReadback(path string) (*os.File, int, bool, error) {
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
	sectorSize, err := logicalSectorSizeForReadback(plain)
	if err != nil || sectorSize <= 0 || zeroBufferSize%sectorSize != 0 {
		return plain, 1, false, nil
	}
	direct, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		return plain, 1, false, nil
	}
	plain.Close()
	return direct, sectorSize, true, nil
}

const blkSSZGetReadback = 0x1268

func logicalSectorSizeForReadback(file *os.File) (int, error) {
	var size int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blkSSZGetReadback, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, errno
	}
	return int(size), nil
}

func directReadUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP)
}

func roundUpInt(value, multiple int) int {
	if multiple <= 1 || value%multiple == 0 {
		return value
	}
	return value + multiple - value%multiple
}

// alignedReadBuffer returns a buffer whose base address satisfies O_DIRECT
// memory-alignment requirements.
func alignedReadBuffer(size, align int) []byte {
	raw := make([]byte, size+align)
	offset := int(uintptr(unsafe.Pointer(&raw[0])) % uintptr(align))
	if offset != 0 {
		offset = align - offset
	}
	return raw[offset : offset+size]
}
