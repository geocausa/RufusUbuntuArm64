//go:build linux

package secureboot

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

type dbxFileIdentity struct {
	device     uint64
	inode      uint64
	size       int64
	modifiedNS int64
	changedNS  int64
}

type dbxReadHook func(*os.File) error

func readStableDBXFile(path string, maxBytes int64) ([]byte, error) {
	return readStableDBXFileWithHook(path, maxBytes, nil)
}

func readStableDBXFileWithHook(path string, maxBytes int64, hook dbxReadHook) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("DBX file size limit must be greater than zero")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open DBX file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open DBX file: invalid file descriptor")
	}
	defer file.Close()

	before, err := dbxIdentityOf(file)
	if err != nil {
		return nil, err
	}
	if before.size > maxBytes {
		return nil, fmt.Errorf("DBX file is too large: %d bytes exceeds the %d-byte limit", before.size, maxBytes)
	}
	if hook != nil {
		if err := hook(file); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read DBX file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("DBX file exceeds the %d-byte limit", maxBytes)
	}
	after, err := dbxIdentityOf(file)
	if err != nil {
		return nil, err
	}
	if before != after || int64(len(data)) != before.size {
		return nil, errors.New("DBX file changed while it was being read")
	}
	return data, nil
}

func dbxIdentityOf(file *os.File) (dbxFileIdentity, error) {
	if file == nil {
		return dbxFileIdentity{}, errors.New("DBX file descriptor is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return dbxFileIdentity{}, fmt.Errorf("stat DBX file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return dbxFileIdentity{}, errors.New("DBX input must be a non-empty regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return dbxFileIdentity{}, errors.New("DBX input has unsupported filesystem metadata")
	}
	return dbxFileIdentity{
		device:     uint64(stat.Dev),
		inode:      stat.Ino,
		size:       info.Size(),
		modifiedNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
		changedNS:  stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec,
	}, nil
}
