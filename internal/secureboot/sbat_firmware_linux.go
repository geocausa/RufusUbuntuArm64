//go:build linux

package secureboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	defaultEFIVarFSRoot                           = "/sys/firmware/efi/efivars"
	shimLockVariableGUID                          = "605dab50-e046-4300-abb6-3dd810dd8b23"
	efiVariableNonVolatile                 uint32 = 1 << 0
	efiVariableBootServiceAccess           uint32 = 1 << 1
	efiVariableRuntimeAccess               uint32 = 1 << 2
	efiVariableTimeBasedAuthenticatedWrite uint32 = 1 << 5
)

type firmwareSBATVariable struct {
	name       string
	path       string
	attributes uint32
	payload    []byte
}

type firmwareSBATReadHook func(stage, path string)

// FirmwareSBATLevel loads the SBAT level exposed by the running shim through
// efivarfs. SbatLevelRT is the preferred operating-system-visible mirror; the
// persistent SbatLevel is an exact fallback only when the firmware exposes it.
func FirmwareSBATLevel() (*SBATLevel, error) {
	return loadFirmwareSBATLevel(defaultEFIVarFSRoot, nil)
}

func loadFirmwareSBATLevel(root string, hook firmwareSBATReadHook) (*SBATLevel, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("efivarfs root is required")
	}

	runtimeVariable, runtimeErr := readFirmwareSBATVariable(root, "SbatLevelRT", hook)
	if runtimeErr != nil && !errors.Is(runtimeErr, os.ErrNotExist) {
		return nil, runtimeErr
	}
	persistentVariable, persistentErr := readFirmwareSBATVariable(root, "SbatLevel", hook)
	if persistentErr != nil && !errors.Is(persistentErr, os.ErrNotExist) {
		return nil, persistentErr
	}
	if runtimeVariable == nil && persistentVariable == nil {
		return nil, errors.New("firmware SBAT level is unavailable; shim may not have published SbatLevelRT or the system may not be booted through shim")
	}
	if runtimeVariable != nil && persistentVariable != nil && !bytes.Equal(runtimeVariable.payload, persistentVariable.payload) {
		return nil, errors.New("firmware SbatLevelRT and SbatLevel payloads differ; refusing an ambiguous enforced SBAT level")
	}

	selected := runtimeVariable
	if selected == nil {
		selected = persistentVariable
	}
	source := fmt.Sprintf("firmware %s (%s; attributes 0x%08x)", selected.name, selected.path, selected.attributes)
	level, err := ParseSBATLevel(selected.payload, source)
	if err != nil {
		return nil, fmt.Errorf("parse firmware %s: %w", selected.name, err)
	}
	return level, nil
}

func readFirmwareSBATVariable(root, name string, hook firmwareSBATReadHook) (*firmwareSBATVariable, error) {
	path := filepath.Join(root, name+"-"+shimLockVariableGUID)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("locate firmware %s variable: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("firmware %s variable must not be a symbolic link", name)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("firmware %s variable is not a regular efivarfs file", name)
	}
	expected, err := uefiIdentityFromInfo(info)
	if err != nil {
		return nil, fmt.Errorf("identify firmware %s variable: %w", name, err)
	}
	if hook != nil {
		hook("before-open", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open firmware %s variable without following links: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create descriptor for firmware %s variable", name)
	}
	defer file.Close()
	actual, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, fmt.Errorf("identify open firmware %s variable: %w", name, err)
	}
	if !sameUEFIKernelObject(expected, actual) {
		return nil, fmt.Errorf("firmware %s variable changed before it was opened", name)
	}
	maximumSize := maximumSBATLevelFileSize + 4
	if actual.size <= 4 || actual.size > maximumSize {
		return nil, fmt.Errorf("firmware %s variable must contain attributes and a non-empty payload no larger than %d bytes", name, maximumSBATLevelFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		return nil, fmt.Errorf("read firmware %s variable: %w", name, err)
	}
	after, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, fmt.Errorf("restat firmware %s variable: %w", name, err)
	}
	if !sameStableUEFIFile(actual, after) || int64(len(data)) != actual.size {
		return nil, fmt.Errorf("firmware %s variable changed while it was being read", name)
	}
	attributes := binary.LittleEndian.Uint32(data[:4])
	if err := validateFirmwareSBATAttributes(name, attributes); err != nil {
		return nil, err
	}
	return &firmwareSBATVariable{
		name:       name,
		path:       path,
		attributes: attributes,
		payload:    append([]byte(nil), data[4:]...),
	}, nil
}

func validateFirmwareSBATAttributes(name string, attributes uint32) error {
	switch name {
	case "SbatLevelRT":
		expected := efiVariableBootServiceAccess | efiVariableRuntimeAccess
		if attributes != expected {
			return fmt.Errorf("firmware SbatLevelRT has attributes 0x%08x; expected exactly boot-service/runtime 0x%08x", attributes, expected)
		}
	case "SbatLevel":
		plain := efiVariableNonVolatile | efiVariableBootServiceAccess
		timeAuthenticated := plain | efiVariableTimeBasedAuthenticatedWrite
		if attributes != plain && attributes != timeAuthenticated {
			return fmt.Errorf("firmware SbatLevel has attributes 0x%08x; expected boot-service/non-volatile 0x%08x or time-authenticated 0x%08x without runtime access", attributes, plain, timeAuthenticated)
		}
	default:
		return fmt.Errorf("unsupported firmware SBAT variable %q", name)
	}
	return nil
}
