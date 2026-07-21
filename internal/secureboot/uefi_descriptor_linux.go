//go:build linux

package secureboot

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	uefiDirectoryReadBatch   = 256
	defaultUEFIMaxEntries    = 32 * 1024
	defaultUEFIMaxDepth      = 64
	defaultUEFIMaxTotalBytes = int64(512 * 1024 * 1024)
)

type uefiTraversalHook func(stage, relative string)

type uefiMediaFile struct {
	relative string
	data     []byte
}

type uefiFileIdentity struct {
	device     uint64
	inode      uint64
	mode       uint32
	size       int64
	modifiedNS int64
	changedNS  int64
}

type uefiTraversalLimits struct {
	maxFiles      int
	maxEntries    int
	maxDepth      int
	maxTotalBytes int64
	entries       int
	totalBytes    int64
}

func newUEFITraversalLimits(maxFiles int) *uefiTraversalLimits {
	return &uefiTraversalLimits{
		maxFiles:      maxFiles,
		maxEntries:    defaultUEFIMaxEntries,
		maxDepth:      defaultUEFIMaxDepth,
		maxTotalBytes: defaultUEFIMaxTotalBytes,
	}
}

func (limits *uefiTraversalLimits) validate() error {
	if limits == nil {
		return errors.New("UEFI traversal limits are required")
	}
	if limits.maxFiles <= 0 || limits.maxFiles > maximumUEFIMaxFiles {
		return fmt.Errorf("UEFI executable limit must be between 1 and %d", maximumUEFIMaxFiles)
	}
	if limits.maxEntries <= 0 || limits.maxEntries > defaultUEFIMaxEntries {
		return fmt.Errorf("UEFI total-entry limit must be between 1 and %d", defaultUEFIMaxEntries)
	}
	if limits.maxDepth <= 0 || limits.maxDepth > defaultUEFIMaxDepth {
		return fmt.Errorf("UEFI directory-depth limit must be between 1 and %d", defaultUEFIMaxDepth)
	}
	if limits.maxTotalBytes <= 0 || limits.maxTotalBytes > defaultUEFIMaxTotalBytes {
		return fmt.Errorf("UEFI aggregate-byte limit must be between 1 and %d", defaultUEFIMaxTotalBytes)
	}
	if limits.entries != 0 || limits.totalBytes != 0 {
		return errors.New("UEFI traversal limits were already used")
	}
	return nil
}

func openUEFIMediaTree(ctx context.Context, root string, maxFiles int, hook uefiTraversalHook) (string, []uefiMediaFile, []string, error) {
	return openUEFIMediaTreeWithLimits(ctx, root, newUEFITraversalLimits(maxFiles), hook)
}

func openUEFIMediaTreeWithLimits(ctx context.Context, root string, limits *uefiTraversalLimits, hook uefiTraversalHook) (string, []uefiMediaFile, []string, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil, nil, errors.New("UEFI media root is required")
	}
	if err := limits.validate(); err != nil {
		return "", nil, nil, err
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("make UEFI media root absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve UEFI media root: %w", err)
	}
	expectedInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, nil, fmt.Errorf("stat UEFI media root: %w", err)
	}
	if !expectedInfo.IsDir() {
		return "", nil, nil, errors.New("UEFI media root is not a directory")
	}
	expected, err := uefiIdentityFromInfo(expectedInfo)
	if err != nil {
		return "", nil, nil, fmt.Errorf("identify UEFI media root: %w", err)
	}
	if hook != nil {
		hook("root-before-open", "")
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, nil, fmt.Errorf("open UEFI media root without following links: %w", err)
	}
	rootFile := os.NewFile(uintptr(fd), resolved)
	if rootFile == nil {
		_ = syscall.Close(fd)
		return "", nil, nil, errors.New("create UEFI media root descriptor")
	}
	defer rootFile.Close()
	actual, err := uefiIdentityFromOpenFile(rootFile)
	if err != nil {
		return "", nil, nil, fmt.Errorf("identify open UEFI media root: %w", err)
	}
	if !sameUEFIKernelObject(expected, actual) {
		return "", nil, nil, errors.New("UEFI media root changed during validation")
	}

	var files []uefiMediaFile
	var warnings []string
	if err := walkUEFIDirectory(ctx, rootFile, "", 0, limits, hook, &files, &warnings); err != nil {
		return "", nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].relative < files[j].relative })
	return resolved, files, warnings, nil
}

func walkUEFIDirectory(ctx context.Context, directory *os.File, prefix string, depth int, limits *uefiTraversalLimits, hook uefiTraversalHook, files *[]uefiMediaFile, warnings *[]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readBoundedUEFIDirectory(ctx, directory, prefix, limits)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return fmt.Errorf("unsafe UEFI directory entry name %q", name)
		}
		relative := filepath.ToSlash(filepath.Join(prefix, name))
		entryInfo, err := os.Lstat(filepath.Join(directory.Name(), name))
		if err != nil {
			return fmt.Errorf("stat UEFI entry %s: %w", relative, err)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			*warnings = append(*warnings, "ignored symbolic link "+relative)
			continue
		}
		if entryInfo.IsDir() {
			if depth >= limits.maxDepth {
				return fmt.Errorf("UEFI media tree exceeds the %d-level directory-depth safety limit at %s", limits.maxDepth, relative)
			}
			if hook != nil {
				hook("entry-before-open", relative)
			}
			child, err := openUEFIEntry(directory, name, entryInfo, true)
			if err != nil {
				return fmt.Errorf("open UEFI directory %s: %w", relative, err)
			}
			err = walkUEFIDirectory(ctx, child, relative, depth+1, limits, hook, files, warnings)
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return fmt.Errorf("close UEFI directory %s: %w", relative, closeErr)
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(name), ".efi") {
			continue
		}
		if !entryInfo.Mode().IsRegular() {
			*warnings = append(*warnings, "ignored non-regular EFI path "+relative)
			continue
		}
		if len(*files) >= limits.maxFiles {
			return fmt.Errorf("more than %d EFI executables found; refusing an unbounded scan", limits.maxFiles)
		}
		remaining := limits.maxTotalBytes - limits.totalBytes
		if entryInfo.Size() < 0 || entryInfo.Size() > remaining {
			return fmt.Errorf("EFI executable bytes exceed the %d-byte aggregate safety limit at %s", limits.maxTotalBytes, relative)
		}
		if hook != nil {
			hook("entry-before-open", relative)
		}
		file, err := openUEFIEntry(directory, name, entryInfo, false)
		if err != nil {
			return fmt.Errorf("open EFI executable %s: %w", relative, err)
		}
		data, readErr := readStableUEFIFile(file)
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read EFI executable %s: %w", relative, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close EFI executable %s: %w", relative, closeErr)
		}
		if int64(len(data)) > remaining {
			return fmt.Errorf("EFI executable bytes exceed the %d-byte aggregate safety limit at %s", limits.maxTotalBytes, relative)
		}
		limits.totalBytes += int64(len(data))
		*files = append(*files, uefiMediaFile{relative: relative, data: data})
	}
	return nil
}

func readBoundedUEFIDirectory(ctx context.Context, directory *os.File, prefix string, limits *uefiTraversalLimits) ([]os.DirEntry, error) {
	entries := make([]os.DirEntry, 0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := directory.ReadDir(uefiDirectoryReadBatch)
		for _, entry := range batch {
			if limits.entries >= limits.maxEntries {
				return nil, fmt.Errorf("more than %d total entries found; refusing an unbounded UEFI media scan", limits.maxEntries)
			}
			limits.entries++
			entries = append(entries, entry)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read UEFI directory %q: %w", prefix, readErr)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func openUEFIEntry(parent *os.File, name string, expectedInfo os.FileInfo, directory bool) (*os.File, error) {
	expected, err := uefiIdentityFromInfo(expectedInfo)
	if err != nil {
		return nil, err
	}
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open without following links: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create descriptor for UEFI entry")
	}
	actual, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	if !sameUEFIKernelObject(expected, actual) {
		file.Close()
		return nil, errors.New("entry changed during validation")
	}
	if directory && actual.mode&syscall.S_IFMT != syscall.S_IFDIR {
		file.Close()
		return nil, errors.New("entry is no longer a directory")
	}
	if !directory && actual.mode&syscall.S_IFMT != syscall.S_IFREG {
		file.Close()
		return nil, errors.New("entry is no longer a regular file")
	}
	return file, nil
}

func readStableUEFIFile(file *os.File) ([]byte, error) {
	before, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, err
	}
	if before.mode&syscall.S_IFMT != syscall.S_IFREG || before.size <= 0 || before.size > maximumUEFIFileSize {
		return nil, fmt.Errorf("EFI executable must be a non-empty regular file no larger than %d bytes", maximumUEFIFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumUEFIFileSize+1))
	if err != nil {
		return nil, err
	}
	after, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, err
	}
	if !sameStableUEFIFile(before, after) || int64(len(data)) != before.size {
		return nil, errors.New("EFI executable changed while it was being read")
	}
	return data, nil
}

func uefiIdentityFromInfo(info os.FileInfo) (uefiFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return uefiFileIdentity{}, errors.New("UEFI path has unsupported filesystem metadata")
	}
	return uefiFileIdentity{
		device:     uint64(stat.Dev),
		inode:      stat.Ino,
		mode:       stat.Mode,
		size:       stat.Size,
		modifiedNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
		changedNS:  stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec,
	}, nil
}

func uefiIdentityFromOpenFile(file *os.File) (uefiFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return uefiFileIdentity{}, err
	}
	return uefiIdentityFromInfo(info)
}

func sameUEFIKernelObject(left, right uefiFileIdentity) bool {
	return left.device == right.device && left.inode == right.inode && left.mode&syscall.S_IFMT == right.mode&syscall.S_IFMT
}

func sameStableUEFIFile(left, right uefiFileIdentity) bool {
	return sameUEFIKernelObject(left, right) && left.size == right.size && left.modifiedNS == right.modifiedNS && left.changedNS == right.changedNS
}

func checkPEData(path string, data []byte, db *Database) CheckResult {
	result := CheckResult{Path: path}
	peHash, err := AuthenticodeSHA256(data)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.AuthenticodeSHA256 = peHash.SHA256
	result.Machine = peHash.Machine
	digestBytes, err := hex.DecodeString(peHash.SHA256)
	if err == nil && len(digestBytes) == sha256.Size {
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		result.DirectHashRevoked = db.IsSHA256Revoked(digest)
	}
	certificates, certErr := embeddedAuthenticodeCertificatesData(data, peHash)
	if certErr != nil {
		result.Error = certErr.Error()
		return result
	}
	result.X509RevocationChecked = true
	result.EmbeddedCertificates = len(certificates)
	for _, certificate := range certificates {
		if db.IsX509Revoked(certificate.Raw) {
			result.X509CertificateRevoked = true
			name := strings.TrimSpace(certificate.Subject.String())
			if name == "" {
				name = certificate.SerialNumber.String()
			}
			result.RevokedCertificates = append(result.RevokedCertificates, name)
		}
	}
	return result
}

func embeddedAuthenticodeCertificatesData(data []byte, hashInfo PEHash) ([]*x509.Certificate, error) {
	if hashInfo.CertificateTableSize == 0 {
		return nil, nil
	}
	start := int(hashInfo.CertificateTableOffset)
	end := start + int(hashInfo.CertificateTableSize)
	if start < 0 || end < start || end > len(data) {
		return nil, errors.New("invalid PE certificate table")
	}
	var result []*x509.Certificate
	for offset := start; offset < end; {
		if end-offset < 8 {
			if allZeroBytes(data[offset:end]) {
				break
			}
			return nil, errors.New("truncated WIN_CERTIFICATE record")
		}
		length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		certificateType := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		if length < 8 || offset+length > end {
			return nil, errors.New("invalid WIN_CERTIFICATE length")
		}
		if certificateType == 0x0002 {
			certs, err := parsePKCS7Certificates(data[offset+8 : offset+length])
			if err != nil {
				return nil, fmt.Errorf("parse Authenticode PKCS#7 certificates: %w", err)
			}
			result = append(result, certs...)
		}
		offset += (length + 7) &^ 7
	}
	return result, nil
}
