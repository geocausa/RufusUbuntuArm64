//go:build linux

package persistence

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"syscall"
)

// DetectPath applies the ordinary persistence detector to a Linux directory
// tree without allowing a special file or raced symlink to block before type
// validation. Every component is opened relative to an already-open root
// descriptor; final components are opened nonblocking.
func DetectPath(root string) (Detection, error) {
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Detection{}, fmt.Errorf("open persistence media root: %w", err)
	}
	defer syscall.Close(rootFD)
	return detect(descriptorFS{rootFD: rootFD})
}

// os.DirFS deliberately exposes only fs.FS. Detect its concrete string-backed
// implementation so existing Linux callers are upgraded without depending on
// them remembering a separate safety API.
func detectPathBackedFS(root fs.FS) (Detection, bool, error) {
	if root == nil {
		return Detection{}, false, nil
	}
	value := reflect.ValueOf(root)
	typeInfo := value.Type()
	if value.Kind() != reflect.String || typeInfo.PkgPath() != "os" || typeInfo.Name() != "dirFS" {
		return Detection{}, false, nil
	}
	detection, err := DetectPath(value.String())
	return detection, true, err
}

type descriptorFS struct {
	rootFD int
}

func (filesystem descriptorFS) Open(name string) (fs.File, error) {
	if filesystem.rootFD < 0 {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		fd, err := syscall.Openat(filesystem.rootFD, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		return fileFromDescriptor(fd, name)
	}
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	current, err := syscall.Openat(filesystem.rootFD, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	components := strings.Split(name, "/")
	for index, component := range components {
		last := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if last {
			flags |= syscall.O_NONBLOCK
		} else {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(current, component, flags, 0)
		closeErr := syscall.Close(current)
		if openErr != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: openErr}
		}
		if closeErr != nil {
			_ = syscall.Close(next)
			return nil, &fs.PathError{Op: "open", Path: name, Err: closeErr}
		}
		current = next
	}
	return fileFromDescriptor(current, name)
}

func fileFromDescriptor(fd int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create persistence media file handle")
	}
	return file, nil
}
