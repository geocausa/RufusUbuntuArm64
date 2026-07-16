//go:build linux

// Package sourcefile binds a selected image path to the exact regular file that
// was inspected before administrator authentication. This prevents a renamed or
// replaced path from silently changing what gets written after confirmation.
package sourcefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Identity contains stable kernel metadata for one regular file snapshot.
// Device and inode catch path replacement; size, modification time, and inode
// change time catch ordinary in-place modifications before the file is pinned.
//
// Once a descriptor has been opened and verified, VerifyPinned deliberately
// ignores ChangedNS. Unlinking, renaming over, chmod, and chown can advance
// ctime without changing a single byte visible through the pinned descriptor.
// Content stability during destructive work is handled separately by hashing
// the pinned descriptor before and while/after it is consumed.
type Identity struct {
	Device     uint64
	Inode      uint64
	Size       int64
	ModifiedNS int64
	ChangedNS  int64
}

// Inspect resolves symlinks, opens the selected file, and records its identity.
func Inspect(path string) (string, Identity, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", Identity{}, fmt.Errorf("make image path absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", Identity{}, fmt.Errorf("resolve image path: %w", err)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", Identity{}, fmt.Errorf("open image: %w", err)
	}
	defer file.Close()
	identity, err := IdentityOf(file)
	if err != nil {
		return "", Identity{}, err
	}
	return resolved, identity, nil
}

// OpenRegular opens path and refuses it if it is no longer the exact regular
// file represented by expected.
func OpenRegular(path string, expected Identity) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}
	if err := Verify(file, expected); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// IdentityOf returns the kernel identity of an already-open regular file.
func IdentityOf(file *os.File) (Identity, error) {
	if file == nil {
		return Identity{}, errors.New("image file is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return Identity{}, fmt.Errorf("stat open image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return Identity{}, errors.New("image must be a non-empty regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, errors.New("image has unsupported filesystem metadata")
	}
	return Identity{
		Device:     uint64(stat.Dev),
		Inode:      stat.Ino,
		Size:       info.Size(),
		ModifiedNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
		ChangedNS:  stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec,
	}, nil
}

// Verify checks that file is still the selected source snapshot. A zero identity
// is accepted for library callers that do not need preflight binding.
func Verify(file *os.File, expected Identity) error {
	if expected == (Identity{}) {
		_, err := IdentityOf(file)
		return err
	}
	actual, err := IdentityOf(file)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("the selected image file changed after confirmation; choose the image again")
	}
	return nil
}

// VerifyPinned checks that an already-open descriptor still refers to the
// same content-sized inode snapshot while allowing metadata-only ctime churn.
// Callers must pair this with a content digest when bytes are consumed across
// a destructive operation.
func VerifyPinned(file *os.File, expected Identity) error {
	if expected == (Identity{}) {
		_, err := IdentityOf(file)
		return err
	}
	actual, err := IdentityOf(file)
	if err != nil {
		return err
	}
	if actual.Device != expected.Device || actual.Inode != expected.Inode || actual.Size != expected.Size || actual.ModifiedNS != expected.ModifiedNS {
		return errors.New("the selected image file changed after confirmation; choose the image again")
	}
	return nil
}
