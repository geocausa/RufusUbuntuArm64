//go:build linux

package acquisition

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

type channelMetadataOpenFunc func(string) (*os.File, error)

func openChannelMetadataNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open acquisition metadata returned an invalid file handle")
	}
	return file, nil
}

func readRegularLimitedWithOpen(path string, limit int, open channelMetadataOpenFunc) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input is not a real regular file")
	}
	file, err := open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, fmt.Errorf("input is not a regular file within the %d-byte limit", limit)
	}
	if !os.SameFile(before, info) {
		return nil, errors.New("input changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	return data, nil
}
