//go:build linux

package persistence

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"
)

const (
	patchSysOpenat2        = 437
	patchResolveNoXDev     = 0x01
	patchResolveNoSymlinks = 0x04
	patchResolveBeneath    = 0x08
	patchOPath             = 0x200000
)

type patchOpenHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// PatchBootConfig adds the detected persistence kernel parameter only to
// kernel-argument lines that already select the matching live-boot family.
// Existing spacing and line endings are preserved as far as possible.
func PatchBootConfig(content string, detection Detection) (string, int, error) {
	if !detection.Ready() {
		return "", 0, errors.New("media does not have a complete supported persistence contract")
	}
	if len(content) > maxConfigBytes {
		return "", 0, fmt.Errorf("boot configuration exceeds the %d-byte patch limit", maxConfigBytes)
	}
	if strings.IndexByte(content, 0) >= 0 || !utf8.ValidString(content) {
		return "", 0, errors.New("boot configuration is not valid UTF-8 text")
	}
	if _, ok := familyBootMarker(detection.Family); !ok {
		return "", 0, fmt.Errorf("unsupported persistence family %q", detection.Family)
	}

	parts := strings.SplitAfter(content, "\n")
	var output strings.Builder
	output.Grow(len(content) + len(parts)*(len(detection.BootParameter)+1))
	changes := 0
	for _, part := range parts {
		body, ending := splitLineEnding(part)
		patched, changed := patchKernelLine(body, detection.Family, detection.BootParameter)
		if changed {
			changes++
		}
		output.WriteString(patched)
		output.WriteString(ending)
	}
	return output.String(), changes, nil
}

func splitLineEnding(line string) (string, string) {
	if strings.HasSuffix(line, "\r\n") {
		return line[:len(line)-2], "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return line[:len(line)-1], "\n"
	}
	return line, ""
}

type tokenSpan struct {
	start int
	end   int
	value string
}

func patchKernelLine(line string, family Family, parameter string) (string, bool) {
	spans := scanTokenSpans(line)
	if len(spans) < 2 || strings.HasPrefix(strings.TrimSpace(line), "#") || !isKernelArgumentCommand(spans[0].value) {
		return line, false
	}
	arguments := make([]string, 0, len(spans)-1)
	insertAt := -1
	for _, span := range spans[1:] {
		if strings.HasPrefix(span.value, "#") {
			if insertAt < 0 {
				insertAt = span.start
			}
			break
		}
		arguments = append(arguments, span.value)
		token := normalizeKernelToken(span.value)
		if kernelTokenMatches(token, parameter) {
			return line, false
		}
		if token == "---" && insertAt < 0 {
			insertAt = span.start
		}
	}
	if !kernelArgumentsSelectFamily(arguments, family) {
		return line, false
	}
	if insertAt >= 0 {
		return line[:insertAt] + parameter + " " + line[insertAt:], true
	}
	trimmed := strings.TrimRight(line, " \t")
	return trimmed + " " + parameter + line[len(trimmed):], true
}

func scanTokenSpans(line string) []tokenSpan {
	spans := make([]tokenSpan, 0, 16)
	for index := 0; index < len(line); {
		for index < len(line) && (line[index] == ' ' || line[index] == '\t') {
			index++
		}
		if index >= len(line) {
			break
		}
		start := index
		for index < len(line) && line[index] != ' ' && line[index] != '\t' {
			index++
		}
		spans = append(spans, tokenSpan{start: start, end: index, value: line[start:index]})
	}
	return spans
}

// PatchBootTree atomically replaces only the paths identified by Detect. The
// root and every parent/final path component are opened without following
// symbolic links. A configuration must still contain a matching live-boot
// kernel line when it is opened for modification.
func PatchBootTree(rootPath string, detection Detection) ([]string, error) {
	if !detection.Ready() {
		return nil, errors.New("media does not have a complete supported persistence contract")
	}
	root, err := openPatchRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open boot tree: %w", err)
	}
	defer root.Close()
	patchedPaths := make([]string, 0, len(detection.PatchPaths))
	for _, relative := range detection.PatchPaths {
		if !filepath.IsLocal(relative) || relative == "." {
			return nil, fmt.Errorf("unsafe boot configuration path %q", relative)
		}
		if err := validatePatchPath(rootPath, relative); err != nil {
			return nil, err
		}
		parent, base, err := openPatchParent(root, relative)
		if err != nil {
			return nil, err
		}
		err = patchOneBootFile(parent, base, relative, detection)
		parent.Close()
		if err != nil {
			return nil, err
		}
		patchedPaths = append(patchedPaths, relative)
	}
	return patchedPaths, nil
}

func validatePatchPath(rootPath, relative string) error {
	current := filepath.Clean(rootPath)
	parts := strings.Split(filepath.Clean(relative), string(os.PathSeparator))
	for index, component := range parts {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("unsafe path component in %s", relative)
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect boot configuration path %s: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("boot configuration path %s contains a symbolic link", relative)
		}
		last := index == len(parts)-1
		if last && !info.Mode().IsRegular() {
			return fmt.Errorf("boot configuration %s is not a regular file", relative)
		}
		if !last && !info.IsDir() {
			return fmt.Errorf("boot configuration parent in %s is not a directory", relative)
		}
	}
	return nil
}

func openPatchRoot(path string) (*os.File, error) {
	fd, err := syscall.Open(path, patchOPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		syscall.Close(fd)
		return nil, errors.New("boot tree root is not a real directory")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openPatchParent(root *os.File, relative string) (*os.File, string, error) {
	clean := filepath.Clean(relative)
	base := filepath.Base(clean)
	parentPath := filepath.Dir(clean)
	if parentPath == "." {
		fd, err := syscall.Openat(int(root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), "."), base, nil
	}
	how := patchOpenHow{
		Flags:   uint64(syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW),
		Resolve: patchResolveNoXDev | patchResolveBeneath | patchResolveNoSymlinks,
	}
	pathPtr, err := syscall.BytePtrFromString(parentPath)
	if err != nil {
		return nil, "", err
	}
	fd, _, errno := syscall.Syscall6(patchSysOpenat2, root.Fd(), uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno == 0 {
		return os.NewFile(fd, parentPath), base, nil
	}
	if errno != syscall.ENOSYS && errno != syscall.EINVAL {
		return nil, "", fmt.Errorf("open parent of %s safely: %w", relative, errno)
	}
	current := int(root.Fd())
	owned := -1
	for _, component := range strings.Split(parentPath, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			if owned >= 0 {
				syscall.Close(owned)
			}
			return nil, "", fmt.Errorf("unsafe path component in %s", relative)
		}
		next, err := syscall.Openat(current, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if owned >= 0 {
				syscall.Close(owned)
			}
			return nil, "", fmt.Errorf("open parent of %s safely: %w", relative, err)
		}
		if owned >= 0 {
			syscall.Close(owned)
		}
		owned = next
		current = next
	}
	return os.NewFile(uintptr(owned), parentPath), base, nil
}

func patchOneBootFile(parent *os.File, base, relative string, detection Detection) error {
	fd, err := syscall.Openat(int(parent.Fd()), base, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open boot configuration %s: %w", relative, err)
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		syscall.Close(fd)
		return errors.New("create boot configuration handle")
	}
	defer file.Close()
	var original syscall.Stat_t
	if err := syscall.Fstat(fd, &original); err != nil {
		return err
	}
	if original.Mode&syscall.S_IFMT != syscall.S_IFREG || original.Size < 0 || original.Size > maxConfigBytes {
		return fmt.Errorf("boot configuration %s is not a bounded regular file", relative)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return fmt.Errorf("read boot configuration %s: %w", relative, err)
	}
	if len(content) > maxConfigBytes {
		return fmt.Errorf("boot configuration %s exceeds the patch limit", relative)
	}
	patched, changes, err := PatchBootConfig(string(content), detection)
	if err != nil {
		return fmt.Errorf("patch boot configuration %s: %w", relative, err)
	}
	if changes == 0 {
		return fmt.Errorf("boot configuration %s no longer contains an unpatched matching kernel line", relative)
	}

	tempName, err := patchTempName(base)
	if err != nil {
		return err
	}
	tempFD, err := syscall.Openat(int(parent.Fd()), tempName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary boot configuration: %w", err)
	}
	keepTemp := true
	defer func() {
		syscall.Close(tempFD)
		if keepTemp {
			_ = syscall.Unlinkat(int(parent.Fd()), tempName)
		}
	}()
	if err := writeFDAll(tempFD, []byte(patched)); err != nil {
		return fmt.Errorf("write temporary boot configuration: %w", err)
	}
	if err := syscall.Fchmod(tempFD, original.Mode&0o777); err != nil {
		return fmt.Errorf("preserve boot configuration mode: %w", err)
	}
	if err := syscall.Fsync(tempFD); err != nil {
		return fmt.Errorf("sync temporary boot configuration: %w", err)
	}

	checkFD, err := syscall.Openat(int(parent.Fd()), base, patchOPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("reopen boot configuration %s: %w", relative, err)
	}
	var current syscall.Stat_t
	statErr := syscall.Fstat(checkFD, &current)
	syscall.Close(checkFD)
	if statErr != nil {
		return statErr
	}
	if current.Dev != original.Dev || current.Ino != original.Ino || current.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("boot configuration %s changed during patching", relative)
	}
	if err := syscall.Renameat(int(parent.Fd()), tempName, int(parent.Fd()), base); err != nil {
		return fmt.Errorf("replace boot configuration %s: %w", relative, err)
	}
	keepTemp = false
	if err := syscall.Fsync(int(parent.Fd())); err != nil {
		return fmt.Errorf("sync boot configuration directory: %w", err)
	}
	return nil
}

func patchTempName(base string) (string, error) {
	var random [8]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("generate temporary boot configuration name: %w", err)
	}
	return "." + base + ".rufusarm64-" + hex.EncodeToString(random[:]), nil
}

func writeFDAll(fd int, data []byte) error {
	for len(data) > 0 {
		written, err := syscall.Write(fd, data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
