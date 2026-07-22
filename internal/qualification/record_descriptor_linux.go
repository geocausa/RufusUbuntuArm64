//go:build linux

package qualification

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	qualificationOPath           = 0x200000
	qualificationRenameNoReplace = uintptr(1)
	metadataTemporaryAttempts    = 128
)

type metadataPairHooks struct {
	BetweenRecordAndChecksum func() error
}

type metadataDirectoryBinding struct {
	directory *os.File
	path      string
	root      *os.File
	rootPath  string
	name      string
}

func writeRecordPairDescriptor(recordPath string, data []byte, digest string) error {
	return writeRecordPairDescriptorWithHooks(recordPath, data, digest, metadataPairHooks{})
}

func writeRecordPairDescriptorWithHooks(recordPath string, data []byte, digest string, hooks metadataPairHooks) (returnErr error) {
	binding, recordName, err := openMetadataDirectoryBinding(recordPath)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, binding.close())
	}()

	checksumName := recordName + ".sha256"
	for _, name := range []string{recordName, checksumName} {
		if err := requireMetadataDestinationAbsentAt(binding.directory, name); err != nil {
			return err
		}
	}

	description := metadataDocumentDescription(recordPath)
	recordIdentity, err := publishMetadataFileAt(binding.directory, recordName, data)
	if err != nil {
		return err
	}
	rollbackRecord := func(cause error) error {
		rollbackErr := removePublishedMetadataAt(binding.directory, recordName, recordIdentity, description)
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback %s: %w", description, rollbackErr))
		}
		return cause
	}

	if hooks.BetweenRecordAndChecksum != nil {
		if err := hooks.BetweenRecordAndChecksum(); err != nil {
			return rollbackRecord(err)
		}
	}
	if err := binding.verify(); err != nil {
		return rollbackRecord(fmt.Errorf("%s directory changed before checksum publication: %w", description, err))
	}

	checksum := []byte(fmt.Sprintf("%s  %s\n", digest, recordName))
	checksumIdentity, err := publishMetadataFileAt(binding.directory, checksumName, checksum)
	if err != nil {
		return rollbackRecord(err)
	}
	if err := binding.verify(); err != nil {
		checksumRollback := removePublishedMetadataAt(binding.directory, checksumName, checksumIdentity, description+" checksum")
		recordRollback := removePublishedMetadataAt(binding.directory, recordName, recordIdentity, description)
		return errors.Join(
			fmt.Errorf("%s directory changed during checksum publication: %w", description, err),
			checksumRollback,
			recordRollback,
		)
	}
	return nil
}

func openMetadataDirectoryBinding(recordPath string) (*metadataDirectoryBinding, string, error) {
	absolute, err := filepath.Abs(recordPath)
	if err != nil {
		return nil, "", err
	}
	parent := filepath.Dir(absolute)
	recordName := filepath.Base(absolute)
	if recordName == "." || recordName == string(filepath.Separator) || !filepath.IsLocal(recordName) {
		return nil, "", errors.New("metadata file name is invalid")
	}

	if recordName == RecordFileName && filepath.Base(parent) == metadataDirName {
		rootPath := filepath.Dir(parent)
		root, err := openValidatedDirectory(rootPath, "metadata root")
		if err != nil {
			return nil, "", err
		}
		directory, err := openValidatedDirectoryAt(root, metadataDirName, parent, "metadata directory")
		if err != nil {
			_ = root.Close()
			return nil, "", err
		}
		return &metadataDirectoryBinding{
			directory: directory,
			path:      parent,
			root:      root,
			rootPath:  rootPath,
			name:      metadataDirName,
		}, recordName, nil
	}

	directory, err := openValidatedDirectory(parent, "metadata parent")
	if err != nil {
		return nil, "", err
	}
	return &metadataDirectoryBinding{directory: directory, path: parent}, recordName, nil
}

func openValidatedDirectory(path, description string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	expected, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.IsDir() {
		return nil, fmt.Errorf("%s must be a real directory", description)
	}
	descriptor, err := syscall.Open(absolute, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(descriptor), absolute)
	current, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if !os.SameFile(expected, current) {
		_ = directory.Close()
		return nil, fmt.Errorf("%s changed before descriptor open", description)
	}
	return directory, nil
}

func openValidatedDirectoryAt(root *os.File, name, path, description string) (*os.File, error) {
	expected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.IsDir() {
		return nil, fmt.Errorf("%s must be a real directory", description)
	}
	descriptor, err := syscall.Openat(int(root.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(descriptor), path)
	current, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if !os.SameFile(expected, current) {
		_ = directory.Close()
		return nil, fmt.Errorf("%s changed before descriptor open", description)
	}
	return directory, nil
}

func (binding *metadataDirectoryBinding) verify() error {
	expected, err := binding.directory.Stat()
	if err != nil {
		return err
	}
	if binding.root != nil {
		rootCurrent, err := openValidatedDirectory(binding.rootPath, "metadata root")
		if err != nil {
			return err
		}
		rootExpected, statErr := binding.root.Stat()
		rootObserved, observedErr := rootCurrent.Stat()
		closeErr := rootCurrent.Close()
		if statErr != nil || observedErr != nil || closeErr != nil {
			return errors.Join(statErr, observedErr, closeErr)
		}
		if !os.SameFile(rootExpected, rootObserved) {
			return errors.New("metadata root no longer names the opened directory")
		}

		current, err := openDirectoryAt(binding.root, binding.name, binding.path)
		if err != nil {
			return err
		}
		observed, statErr := current.Stat()
		closeErr = current.Close()
		if statErr != nil || closeErr != nil {
			return errors.Join(statErr, closeErr)
		}
		if !os.SameFile(expected, observed) {
			return errors.New("metadata directory no longer names the opened directory")
		}
		return nil
	}

	current, err := openValidatedDirectory(binding.path, "metadata parent")
	if err != nil {
		return err
	}
	observed, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !os.SameFile(expected, observed) {
		return errors.New("metadata parent no longer names the opened directory")
	}
	return nil
}

func (binding *metadataDirectoryBinding) close() error {
	if binding == nil {
		return nil
	}
	var errs []error
	if binding.directory != nil {
		errs = append(errs, binding.directory.Close())
	}
	if binding.root != nil {
		errs = append(errs, binding.root.Close())
	}
	return errors.Join(errs...)
}

func openDirectoryAt(root *os.File, name, displayPath string) (*os.File, error) {
	descriptor, err := syscall.Openat(int(root.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), displayPath), nil
}

func requireMetadataDestinationAbsentAt(directory *os.File, name string) error {
	descriptor, err := syscall.Openat(int(directory.Fd()), name, qualificationOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = syscall.Close(descriptor)
	return fmt.Errorf("metadata file %s already exists", name)
}

func publishMetadataFileAt(directory *os.File, destination string, data []byte) (os.FileInfo, error) {
	temporary, identity, err := stageMetadataFileAt(directory, data)
	if err != nil {
		return nil, err
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = syscall.Unlinkat(int(directory.Fd()), temporary)
		}
	}()

	if err := renameMetadataAtNoReplace(directory, temporary, destination); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil, errors.New("metadata destination appeared during write")
		}
		return nil, err
	}
	cleanupTemporary = false
	if err := verifyPublishedMetadataAt(directory, destination, identity); err != nil {
		rollbackErr := removePublishedMetadataAt(directory, destination, identity, "metadata file")
		return nil, errors.Join(err, rollbackErr)
	}
	if err := directory.Sync(); err != nil {
		rollbackErr := removePublishedMetadataAt(directory, destination, identity, "metadata file")
		return nil, errors.Join(err, rollbackErr)
	}
	return identity, nil
}

func stageMetadataFileAt(directory *os.File, data []byte) (string, os.FileInfo, error) {
	for attempt := 0; attempt < metadataTemporaryAttempts; attempt++ {
		randomBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
			return "", nil, err
		}
		name := ".rufusarm64-metadata-" + hex.EncodeToString(randomBytes)
		descriptor, err := syscall.Openat(
			int(directory.Fd()),
			name,
			syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0o600,
		)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		file := os.NewFile(uintptr(descriptor), name)
		cleanup := true
		defer func() {
			if cleanup {
				_ = file.Close()
				_ = syscall.Unlinkat(int(directory.Fd()), name)
			}
		}()
		written, err := file.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return "", nil, err
		}
		if err := file.Sync(); err != nil {
			return "", nil, err
		}
		identity, err := file.Stat()
		if err != nil {
			return "", nil, err
		}
		if !identity.Mode().IsRegular() {
			return "", nil, errors.New("metadata temporary is not a regular file")
		}
		if err := file.Close(); err != nil {
			return "", nil, err
		}
		cleanup = false
		return name, identity, nil
	}
	return "", nil, errors.New("could not allocate a private metadata temporary file")
}

func verifyPublishedMetadataAt(directory *os.File, name string, expected os.FileInfo) error {
	current, err := openMetadataRegularAt(directory, name)
	if err != nil {
		return err
	}
	observed, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !os.SameFile(expected, observed) {
		return errors.New("published metadata file changed before verification")
	}
	return nil
}

func removePublishedMetadataAt(directory *os.File, name string, expected os.FileInfo, description string) error {
	current, err := openMetadataRegularAt(directory, name)
	if err != nil {
		return fmt.Errorf("reinspect %s for rollback: %w", description, err)
	}
	observed, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !os.SameFile(expected, observed) {
		return fmt.Errorf("%s changed before rollback; refusing to remove it", description)
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return fmt.Errorf("remove incomplete %s: %w", description, err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync metadata directory after rollback: %w", err)
	}
	return nil
}

func openMetadataRegularAt(directory *os.File, name string) (*os.File, error) {
	descriptor, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("metadata file is not a regular file")
	}
	return file, nil
}

func qualificationRenameat2Trap() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 316, nil
	case "arm64":
		return 276, nil
	default:
		return 0, fmt.Errorf("descriptor-relative metadata publication is unsupported on linux/%s", runtime.GOARCH)
	}
}

func renameMetadataAtNoReplace(directory *os.File, source, destination string) error {
	trap, err := qualificationRenameat2Trap()
	if err != nil {
		return err
	}
	sourcePointer, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.BytePtrFromString(destination)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		trap,
		directory.Fd(),
		uintptr(unsafe.Pointer(sourcePointer)),
		directory.Fd(),
		uintptr(unsafe.Pointer(destinationPointer)),
		qualificationRenameNoReplace,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(destinationPointer)
	if errno != 0 {
		return errno
	}
	return nil
}
