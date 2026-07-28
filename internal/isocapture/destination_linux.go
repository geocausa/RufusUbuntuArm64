//go:build linux

package isocapture

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/geocausa/RufusArm64/internal/safety"
)

const (
	isoRenameNoReplace = 1
	isoRenameat2AMD64  = 316
	isoRenameat2ARM64  = 276
)

type destinationPlan struct {
	Path           string
	Name           string
	AvailableBytes uint64
	RequiredBytes  uint64
	Directory      *os.File
}

func prepareISODestination(outputPath, sourceDevicePath string, requiredBytes uint64) (destinationPlan, error) {
	if requiredBytes == 0 {
		return destinationPlan{}, errors.New("ISO destination requires a positive conservative size")
	}
	clean := filepath.Clean(outputPath)
	if outputPath == "" || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return destinationPlan{}, errors.New("ISO destination must be an absolute file path")
	}
	name := filepath.Base(clean)
	if !filepath.IsLocal(name) || name == "." || !strings.EqualFold(filepath.Ext(name), ".iso") {
		return destinationPlan{}, errors.New("ISO destination must name a local .iso file")
	}
	if sourceDevicePath == "" || !filepath.IsAbs(filepath.Clean(sourceDevicePath)) {
		return destinationPlan{}, errors.New("ISO destination validation requires an absolute source-device path")
	}
	parent := filepath.Dir(clean)
	pathInfo, err := os.Lstat(parent)
	if err != nil {
		return destinationPlan{}, fmt.Errorf("inspect ISO destination directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return destinationPlan{}, errors.New("ISO destination parent must be a real directory")
	}
	directory, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return destinationPlan{}, fmt.Errorf("open ISO destination directory: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = directory.Close()
		}
	}()
	openInfo, err := directory.Stat()
	if err != nil {
		return destinationPlan{}, fmt.Errorf("inspect open ISO destination directory: %w", err)
	}
	if !openInfo.IsDir() || !os.SameFile(pathInfo, openInfo) {
		return destinationPlan{}, errors.New("ISO destination directory changed during validation")
	}
	if err := safety.EnsurePathNotOnTarget(isoDescriptorPath(directory), sourceDevicePath); err != nil {
		return destinationPlan{}, fmt.Errorf("validate ISO destination storage: %w", err)
	}
	if err := validateGraphicalISODirectory(directory); err != nil {
		return destinationPlan{}, err
	}
	available, err := availableBytes(directory)
	if err != nil {
		return destinationPlan{}, err
	}
	if available < requiredBytes {
		return destinationPlan{}, fmt.Errorf("ISO destination has %d bytes available but %d bytes are conservatively required", available, requiredBytes)
	}
	if err := requireISOAbsent(directory, name); err != nil {
		return destinationPlan{}, err
	}
	closeOnError = false
	return destinationPlan{
		Path:           clean,
		Name:           name,
		AvailableBytes: available,
		RequiredBytes:  requiredBytes,
		Directory:      directory,
	}, nil
}

func isoDescriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
}

func availableBytes(directory *os.File) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return 0, fmt.Errorf("inspect ISO destination free space: %w", err)
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("ISO destination reported an invalid filesystem block size")
	}
	blockSize := uint64(stat.Bsize)
	blocks := uint64(stat.Bavail)
	if blocks > math.MaxUint64/blockSize {
		return math.MaxUint64, nil
	}
	return blocks * blockSize, nil
}

func requireISOAbsent(directory *os.File, name string) error {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("ISO destination already exists: %s", name)
	}
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return fmt.Errorf("ISO destination already exists or cannot be inspected: %s: %w", name, err)
}

func (destination destinationPlan) createTemporary() (*os.File, string, error) {
	temporary, err := os.CreateTemp(isoDescriptorPath(destination.Directory), "."+destination.Name+".rufusarm64-partial-*")
	if err != nil {
		return nil, "", fmt.Errorf("create private ISO destination: %w", err)
	}
	name := filepath.Base(temporary.Name())
	cleanup := func() {
		_ = temporary.Close()
		_ = syscall.Unlinkat(int(destination.Directory.Fd()), name)
	}
	if !filepath.IsLocal(name) {
		cleanup()
		return nil, "", errors.New("ISO temporary destination has an invalid name")
	}
	info, err := temporary.Stat()
	if err != nil {
		cleanup()
		return nil, "", fmt.Errorf("inspect ISO temporary destination: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
		cleanup()
		return nil, "", errors.New("ISO temporary destination is not a private single-link regular file")
	}
	if info.Mode().Perm() != 0o600 {
		if err := temporary.Chmod(0o600); err != nil {
			cleanup()
			return nil, "", fmt.Errorf("secure ISO temporary destination: %w", err)
		}
	}
	return temporary, name, nil
}

func (destination destinationPlan) revalidate() error {
	pathInfo, err := os.Lstat(filepath.Dir(destination.Path))
	if err != nil {
		return fmt.Errorf("reinspect ISO destination directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return errors.New("ISO destination directory is no longer a real directory")
	}
	openInfo, err := destination.Directory.Stat()
	if err != nil {
		return fmt.Errorf("reinspect open ISO destination directory: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		return errors.New("ISO destination directory changed before publication")
	}
	return requireISOAbsent(destination.Directory, destination.Name)
}

type isoPublicationOps struct {
	rename func(*os.File, string, string) error
	sync   func(*os.File) error
	unlink func(*os.File, string) error
}

func publishISONoReplace(directory *os.File, temporaryName, destinationName string) error {
	return publishISONoReplaceWith(directory, temporaryName, destinationName, isoPublicationOps{
		rename: isoRenameNoReplaceAt,
		sync: func(open *os.File) error {
			return open.Sync()
		},
		unlink: func(open *os.File, name string) error {
			return syscall.Unlinkat(int(open.Fd()), name)
		},
	})
}

func publishISONoReplaceWith(directory *os.File, temporaryName, destinationName string, operations isoPublicationOps) error {
	if operations.rename == nil || operations.sync == nil || operations.unlink == nil {
		return errors.New("ISO publication operations are incomplete")
	}
	if err := operations.rename(directory, temporaryName, destinationName); err != nil {
		return err
	}
	if syncErr := operations.sync(directory); syncErr != nil {
		result := error(fmt.Errorf("sync ISO destination directory: %w", syncErr))
		if unlinkErr := operations.unlink(directory, destinationName); unlinkErr != nil {
			result = errors.Join(result, fmt.Errorf("rollback published ISO destination: %w", unlinkErr))
		}
		if rollbackSyncErr := operations.sync(directory); rollbackSyncErr != nil {
			result = errors.Join(result, fmt.Errorf("sync ISO destination directory after rollback: %w", rollbackSyncErr))
		}
		return result
	}
	return nil
}

func isoRenameNoReplaceAt(directory *os.File, temporaryName, destinationName string) error {
	syscallNumber, err := isoRenameat2Number()
	if err != nil {
		return err
	}
	temporaryPointer, err := syscall.BytePtrFromString(temporaryName)
	if err != nil {
		return fmt.Errorf("encode ISO temporary name: %w", err)
	}
	destinationPointer, err := syscall.BytePtrFromString(destinationName)
	if err != nil {
		return fmt.Errorf("encode ISO destination name: %w", err)
	}
	directoryFD := uintptr(directory.Fd())
	_, _, errno := syscall.Syscall6(
		syscallNumber,
		directoryFD,
		uintptr(unsafe.Pointer(temporaryPointer)),
		directoryFD,
		uintptr(unsafe.Pointer(destinationPointer)),
		isoRenameNoReplace,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("publish ISO without replacing an existing file: %w", errno)
	}
	return nil
}

func isoRenameat2Number() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return isoRenameat2AMD64, nil
	case "arm64":
		return isoRenameat2ARM64, nil
	default:
		return 0, fmt.Errorf("atomic no-replace ISO publication is unsupported on linux/%s", runtime.GOARCH)
	}
}

func validateGraphicalISODirectory(directory *os.File) error {
	uidText := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uidText == "" {
		return nil
	}
	uid, groups, err := graphicalISOCredentials(uidText)
	if err != nil {
		return err
	}
	info, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect graphical ISO destination directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("graphical ISO destination is not a Linux directory")
	}
	permissions := stat.Mode & 0o7
	if stat.Uid == uint32(uid) {
		permissions = (stat.Mode >> 6) & 0o7
	} else if _, ok := groups[stat.Gid]; ok {
		permissions = (stat.Mode >> 3) & 0o7
	}
	if permissions&0o3 != 0o3 {
		return fmt.Errorf("graphical ISO destination directory is not writable and searchable by desktop user %d", uid)
	}
	return nil
}

func graphicalISOCredentials(uidText string) (int, map[uint32]struct{}, error) {
	uid64, err := strconv.ParseInt(strings.TrimSpace(uidText), 10, 32)
	if err != nil || uid64 < 0 {
		return 0, nil, fmt.Errorf("invalid PKEXEC_UID %q", uidText)
	}
	uid := int(uid64)
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve graphical ISO user %d: %w", uid, err)
	}
	groupTexts, err := account.GroupIds()
	if err != nil {
		return 0, nil, fmt.Errorf("resolve graphical ISO groups for user %d: %w", uid, err)
	}
	groupTexts = append(groupTexts, account.Gid)
	groups := make(map[uint32]struct{}, len(groupTexts))
	for _, groupText := range groupTexts {
		group64, err := strconv.ParseUint(strings.TrimSpace(groupText), 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("graphical ISO user %d has invalid group %q", uid, groupText)
		}
		groups[uint32(group64)] = struct{}{}
	}
	return uid, groups, nil
}

func applyGraphicalISOOwner(file *os.File) error {
	uidText := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uidText == "" {
		return nil
	}
	uid64, err := strconv.ParseInt(uidText, 10, 32)
	if err != nil || uid64 < 0 {
		return fmt.Errorf("invalid PKEXEC_UID %q", uidText)
	}
	uid := int(uid64)
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect ISO ownership: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ISO destination has no Linux ownership metadata")
	}
	if int(stat.Uid) != uid {
		if err := file.Chown(uid, -1); err != nil {
			return fmt.Errorf("assign ISO image to graphical user: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync ISO image ownership: %w", err)
	}
	info, err = file.Stat()
	if err != nil {
		return fmt.Errorf("verify ISO ownership: %w", err)
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return fmt.Errorf("verify ISO image ownership for graphical user %d", uid)
	}
	return nil
}
