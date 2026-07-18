//go:build linux

package runtimeintegrity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/secureboot"
)

const (
	arm64FallbackName = "BOOTAA64.EFI"
	arm64OriginalName = "bootaa64_original.efi"
)

type installMutationState struct {
	backupPublished   bool
	wrapperReplaced   bool
	manifestPublished bool
	temporary         []temporaryFile
}

type temporaryFile struct {
	directory *os.File
	name      string
}

// InstallARM64 atomically wraps an existing ARM64 removable-media fallback
// loader in an explicitly pinned runtime-integrity loader.
func InstallARM64(ctx context.Context, root string, asset LoaderAsset, opts TransactionOptions) (InstallResult, error) {
	return installARM64(ctx, root, asset, opts)
}

func installARM64(ctx context.Context, root string, asset LoaderAsset, opts TransactionOptions) (result InstallResult, returnErr error) {
	if ctx == nil {
		return InstallResult{}, errors.New("runtime-integrity installation context is nil")
	}
	expectedWrapper, err := normalizedSHA256(asset.ExpectedSHA256)
	if err != nil {
		return InstallResult{}, fmt.Errorf("loader asset digest: %w", err)
	}
	if len(asset.Data) == 0 || len(asset.Data) > maximumLoaderSize {
		return InstallResult{}, fmt.Errorf("loader asset must be between 1 and %d bytes", maximumLoaderSize)
	}
	if actual := sha256Hex(asset.Data); actual != expectedWrapper {
		return InstallResult{}, fmt.Errorf("loader asset SHA-256 is %s, expected %s", actual, expectedWrapper)
	}
	if err := requireARM64EFIApplication(asset.Data, "runtime-integrity loader"); err != nil {
		return InstallResult{}, err
	}

	resolved, rootFile, rootIdentity, err := openTransactionRoot(root)
	if err != nil {
		return InstallResult{}, err
	}
	defer rootFile.Close()
	boot, err := openExactDirectoryPath(rootFile, "EFI/BOOT")
	if err != nil {
		return InstallResult{}, err
	}
	defer boot.Close()
	if err := ensureCaseAbsent(rootFile, ManifestName); err != nil {
		return InstallResult{}, err
	}
	if err := ensureCaseAbsent(boot, arm64OriginalName); err != nil {
		return InstallResult{}, err
	}
	originalData, originalIdentity, err := readExactRegular(boot, arm64FallbackName, maximumLoaderSize)
	if err != nil {
		return InstallResult{}, fmt.Errorf("read original ARM64 fallback loader: %w", err)
	}
	if err := requireARM64EFIApplication(originalData, "original ARM64 fallback loader"); err != nil {
		return InstallResult{}, err
	}
	originalMode := uint32(originalIdentity.mode & 0o777)
	if originalMode == 0 {
		originalMode = 0o644
	}

	state := &installMutationState{}
	defer func() {
		if returnErr == nil {
			return
		}
		if rollbackErr := rollbackInstall(rootFile, boot, originalData, originalMode, state); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback runtime-integrity installation: %w", rollbackErr))
		}
	}()
	if err := transactionStage(opts, "validated"); err != nil {
		return InstallResult{}, err
	}

	backupTemp, err := writeTemporary(boot, ".rufusarm64-original-", originalData, originalMode)
	if err != nil {
		return InstallResult{}, fmt.Errorf("stage original fallback loader: %w", err)
	}
	state.temporary = append(state.temporary, temporaryFile{directory: boot, name: backupTemp})
	if err := publishNoReplace(boot, backupTemp, arm64OriginalName); err != nil {
		return InstallResult{}, fmt.Errorf("publish original fallback backup: %w", err)
	}
	state.temporary = removeTemporary(state.temporary, boot, backupTemp)
	state.backupPublished = true
	if err := syncDirectory(boot); err != nil {
		return InstallResult{}, err
	}
	if err := transactionStage(opts, "backup-published"); err != nil {
		return InstallResult{}, err
	}

	wrapperTemp, err := writeTemporary(boot, ".rufusarm64-wrapper-", asset.Data, 0o644)
	if err != nil {
		return InstallResult{}, fmt.Errorf("stage runtime-integrity loader: %w", err)
	}
	state.temporary = append(state.temporary, temporaryFile{directory: boot, name: wrapperTemp})
	if err := replaceFromTemporary(boot, wrapperTemp, arm64FallbackName); err != nil {
		return InstallResult{}, fmt.Errorf("replace ARM64 fallback loader: %w", err)
	}
	state.temporary = removeTemporary(state.temporary, boot, wrapperTemp)
	state.wrapperReplaced = true
	if err := syncDirectory(boot); err != nil {
		return InstallResult{}, err
	}
	if err := transactionStage(opts, "wrapper-replaced"); err != nil {
		return InstallResult{}, err
	}

	manifest, err := generateFromOpenRoot(ctx, rootFile, rootIdentity, opts.MaxFiles)
	if err != nil {
		return InstallResult{}, fmt.Errorf("generate installed runtime-integrity manifest: %w", err)
	}
	standardManifest, err := manifest.MarshalText()
	if err != nil {
		return InstallResult{}, err
	}
	record := InstallationRecord{
		Schema:                      1,
		Architecture:                "arm64",
		FallbackPath:                ARM64FallbackPath,
		OriginalPath:                ARM64OriginalPath,
		OriginalSHA256:              sha256Hex(originalData),
		OriginalSize:                uint64(len(originalData)),
		OriginalMode:                originalMode,
		WrapperSHA256:               expectedWrapper,
		WrapperSize:                 uint64(len(asset.Data)),
		WrapperSourceCommit:         strings.TrimSpace(asset.SourceCommit),
		WrapperProvenance:           strings.TrimSpace(asset.Provenance),
		WrapperSecureBootCompatible: asset.SecureBootCompatible,
		ManifestRecordsSHA256:       sha256Hex(standardManifest),
	}
	installedManifest, err := marshalInstalledManifest(standardManifest, record)
	if err != nil {
		return InstallResult{}, err
	}
	if err := transactionStage(opts, "manifest-generated"); err != nil {
		return InstallResult{}, err
	}
	manifestTemp, err := writeTemporary(rootFile, ".rufusarm64-manifest-", installedManifest, 0o644)
	if err != nil {
		return InstallResult{}, fmt.Errorf("stage runtime-integrity manifest: %w", err)
	}
	state.temporary = append(state.temporary, temporaryFile{directory: rootFile, name: manifestTemp})
	if err := publishNoReplace(rootFile, manifestTemp, ManifestName); err != nil {
		return InstallResult{}, fmt.Errorf("publish runtime-integrity manifest: %w", err)
	}
	state.temporary = removeTemporary(state.temporary, rootFile, manifestTemp)
	state.manifestPublished = true
	if err := syncDirectory(rootFile); err != nil {
		return InstallResult{}, err
	}
	if err := transactionStage(opts, "manifest-published"); err != nil {
		return InstallResult{}, err
	}

	verification, err := verifyFromOpenRoot(ctx, rootFile, rootIdentity, opts.MaxFiles)
	if err != nil {
		return InstallResult{}, fmt.Errorf("verify installed runtime-integrity manifest: %w", err)
	}
	if !verification.Valid {
		return InstallResult{}, fmt.Errorf("installed runtime-integrity manifest is invalid: %s", strings.Join(verification.Errors, "; "))
	}
	if err := ensureRootIdentity(rootFile, rootIdentity); err != nil {
		return InstallResult{}, err
	}
	if err := transactionStage(opts, "verified"); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{
		Root:           resolved,
		Record:         record,
		ManifestSHA256: sha256Hex(installedManifest),
		Verification:   verification,
	}, nil
}

// RemoveARM64 restores the original fallback loader only when the complete
// installed state still matches the embedded record and manifest.
func RemoveARM64(ctx context.Context, root string, opts TransactionOptions) (result RemovalResult, returnErr error) {
	if ctx == nil {
		return RemovalResult{}, errors.New("runtime-integrity removal context is nil")
	}
	resolved, rootFile, rootIdentity, err := openTransactionRoot(root)
	if err != nil {
		return RemovalResult{}, err
	}
	defer rootFile.Close()
	boot, err := openExactDirectoryPath(rootFile, "EFI/BOOT")
	if err != nil {
		return RemovalResult{}, err
	}
	defer boot.Close()

	manifestData, _, err := readExactRegular(rootFile, ManifestName, MaximumManifestSize)
	if err != nil {
		return RemovalResult{}, fmt.Errorf("read installed manifest: %w", err)
	}
	record, _, err := parseInstallationRecord(manifestData)
	if err != nil {
		return RemovalResult{}, err
	}
	verification, err := verifyFromOpenRoot(ctx, rootFile, rootIdentity, opts.MaxFiles)
	if err != nil {
		return RemovalResult{}, err
	}
	if !verification.Valid {
		return RemovalResult{}, fmt.Errorf("refuse removal because installed media integrity is invalid: %s", strings.Join(verification.Errors, "; "))
	}
	wrapperData, _, err := readExactRegular(boot, arm64FallbackName, maximumLoaderSize)
	if err != nil {
		return RemovalResult{}, err
	}
	originalData, originalIdentity, err := readExactRegular(boot, arm64OriginalName, maximumLoaderSize)
	if err != nil {
		return RemovalResult{}, err
	}
	if sha256Hex(wrapperData) != record.WrapperSHA256 || uint64(len(wrapperData)) != record.WrapperSize {
		return RemovalResult{}, errors.New("active runtime-integrity loader no longer matches the installation record")
	}
	if sha256Hex(originalData) != record.OriginalSHA256 || uint64(len(originalData)) != record.OriginalSize {
		return RemovalResult{}, errors.New("original fallback-loader backup no longer matches the installation record")
	}
	if err := requireARM64EFIApplication(wrapperData, "installed runtime-integrity loader"); err != nil {
		return RemovalResult{}, err
	}
	if err := requireARM64EFIApplication(originalData, "backed-up original fallback loader"); err != nil {
		return RemovalResult{}, err
	}
	originalMode := uint32(originalIdentity.mode & 0o777)
	if originalMode == 0 {
		originalMode = record.OriginalMode
	}
	mutated := false
	defer func() {
		if returnErr == nil || !mutated {
			return
		}
		if rollbackErr := restoreInstalledState(rootFile, boot, wrapperData, originalData, originalMode, manifestData); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback runtime-integrity removal: %w", rollbackErr))
		}
	}()

	if err := atomicReplace(boot, arm64FallbackName, originalData, originalMode); err != nil {
		return RemovalResult{}, fmt.Errorf("restore original fallback loader: %w", err)
	}
	mutated = true
	if err := syncDirectory(boot); err != nil {
		return RemovalResult{}, err
	}
	if err := transactionStage(opts, "remove-original-restored"); err != nil {
		return RemovalResult{}, err
	}
	if err := removeExact(boot, arm64OriginalName); err != nil {
		return RemovalResult{}, fmt.Errorf("remove original fallback backup: %w", err)
	}
	if err := syncDirectory(boot); err != nil {
		return RemovalResult{}, err
	}
	if err := transactionStage(opts, "remove-backup-removed"); err != nil {
		return RemovalResult{}, err
	}
	if err := removeExact(rootFile, ManifestName); err != nil {
		return RemovalResult{}, fmt.Errorf("remove runtime-integrity manifest: %w", err)
	}
	if err := syncDirectory(rootFile); err != nil {
		return RemovalResult{}, err
	}
	if err := transactionStage(opts, "remove-manifest-removed"); err != nil {
		return RemovalResult{}, err
	}

	restored, _, err := readExactRegular(boot, arm64FallbackName, maximumLoaderSize)
	if err != nil {
		return RemovalResult{}, err
	}
	if sha256Hex(restored) != record.OriginalSHA256 {
		return RemovalResult{}, errors.New("restored fallback loader digest does not match the installation record")
	}
	if err := ensureCaseAbsent(boot, arm64OriginalName); err != nil {
		return RemovalResult{}, err
	}
	if err := ensureCaseAbsent(rootFile, ManifestName); err != nil {
		return RemovalResult{}, err
	}
	if err := ensureRootIdentity(rootFile, rootIdentity); err != nil {
		return RemovalResult{}, err
	}
	if err := transactionStage(opts, "remove-verified"); err != nil {
		return RemovalResult{}, err
	}
	return RemovalResult{Root: resolved, RestoredSHA256: record.OriginalSHA256, RemovedManifestSHA256: sha256Hex(manifestData)}, nil
}

func requireARM64EFIApplication(data []byte, label string) error {
	info, err := secureboot.InspectEFIImage(data)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if info.Machine != secureboot.MachineARM64 {
		return fmt.Errorf("%s is %s, expected ARM64", label, info.MachineName)
	}
	if info.Subsystem != secureboot.SubsystemEFIApplication {
		return fmt.Errorf("%s subsystem is %s, expected EFI application", label, info.SubsystemName)
	}
	return nil
}

func transactionStage(opts TransactionOptions, stage string) error {
	if opts.hook == nil {
		return nil
	}
	if err := opts.hook(stage); err != nil {
		return fmt.Errorf("injected transaction failure at %s: %w", stage, err)
	}
	return nil
}

func openTransactionRoot(root string) (string, *os.File, fileIdentity, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil, fileIdentity{}, errors.New("media root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, fileIdentity{}, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, fileIdentity{}, fmt.Errorf("resolve media root: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, fileIdentity{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fileIdentity{}, errors.New("media root is not a real directory")
	}
	expected, err := identityFromInfo(info)
	if err != nil {
		return "", nil, fileIdentity{}, err
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), resolved)
	if file == nil {
		_ = syscall.Close(fd)
		return "", nil, fileIdentity{}, errors.New("create media root descriptor")
	}
	actual, err := identityFromOpenFile(file)
	if err != nil || !sameKernelObject(expected, actual) {
		file.Close()
		if err != nil {
			return "", nil, fileIdentity{}, err
		}
		return "", nil, fileIdentity{}, errors.New("media root changed while it was opened")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return "", nil, fileIdentity{}, fmt.Errorf("lock media root: %w", err)
	}
	return resolved, file, actual, nil
}

func openExactDirectoryPath(root *os.File, relative string) (*os.File, error) {
	current, err := reopenDirectory(root)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		entry, info, err := exactEntry(current, part)
		if err != nil {
			current.Close()
			return nil, err
		}
		if !entry.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, fmt.Errorf("%s is not a real directory", part)
		}
		next, err := openEntry(current, part, info, true)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func reopenDirectory(directory *os.File) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), directory.Name())
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("reopen directory descriptor")
	}
	expected, err := identityFromOpenFile(directory)
	if err != nil {
		file.Close()
		return nil, err
	}
	actual, err := identityFromOpenFile(file)
	if err != nil || !sameKernelObject(expected, actual) {
		file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("directory changed while it was reopened")
	}
	return file, nil
}

func exactEntry(directory *os.File, expected string) (os.DirEntry, os.FileInfo, error) {
	listing, err := reopenDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	defer listing.Close()
	entries, err := listing.ReadDir(-1)
	if err != nil {
		return nil, nil, err
	}
	var match os.DirEntry
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), expected) {
			continue
		}
		if match != nil {
			return nil, nil, fmt.Errorf("directory contains multiple case-equivalent %q entries", expected)
		}
		if entry.Name() != expected {
			return nil, nil, fmt.Errorf("directory entry %q must use exact spelling %q", entry.Name(), expected)
		}
		match = entry
	}
	if match == nil {
		return nil, nil, os.ErrNotExist
	}
	info, err := match.Info()
	if err != nil {
		return nil, nil, err
	}
	return match, info, nil
}

func ensureCaseAbsent(directory *os.File, expected string) error {
	_, _, err := exactEntry(directory, expected)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("refuse ambiguous pre-existing %s", expected)
}

func readExactRegular(directory *os.File, name string, maximum int) ([]byte, fileIdentity, error) {
	entry, info, err := exactEntry(directory, name)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if entry.IsDir() || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fileIdentity{}, errors.New("entry is not a regular file")
	}
	file, err := openEntry(directory, name, info, false)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	defer file.Close()
	identity, err := identityFromOpenFile(file)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if identity.size <= 0 || identity.size > int64(maximum) {
		return nil, fileIdentity{}, fmt.Errorf("file size must be between 1 and %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, fileIdentity{}, err
	}
	after, err := identityFromOpenFile(file)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if !sameStableObject(identity, after) || len(data) != int(identity.size) {
		return nil, fileIdentity{}, errors.New("file changed while it was being read")
	}
	return data, identity, nil
}

func randomTemporaryName(prefix string) (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func writeTemporary(directory *os.File, prefix string, data []byte, mode uint32) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomTemporaryName(prefix)
		if err != nil {
			return "", err
		}
		fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", err
		}
		file := os.NewFile(uintptr(fd), filepath.Join(directory.Name(), name))
		if file == nil {
			_ = syscall.Close(fd)
			return "", errors.New("create temporary file descriptor")
		}
		_, writeErr := file.Write(data)
		if writeErr == nil {
			writeErr = file.Chmod(os.FileMode(mode))
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = removeExact(directory, name)
			return "", errors.Join(writeErr, closeErr)
		}
		return name, nil
	}
	return "", errors.New("could not allocate a private transaction filename")
}

func descriptorPath(directory *os.File, name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), name)
}

func publishNoReplace(directory *os.File, temporary, target string) error {
	if err := os.Link(descriptorPath(directory, temporary), descriptorPath(directory, target)); err != nil {
		return err
	}
	return removeExact(directory, temporary)
}

func replaceFromTemporary(directory *os.File, temporary, target string) error {
	return os.Rename(descriptorPath(directory, temporary), descriptorPath(directory, target))
}

func atomicReplace(directory *os.File, target string, data []byte, mode uint32) error {
	temporary, err := writeTemporary(directory, ".rufusarm64-replace-", data, mode)
	if err != nil {
		return err
	}
	if err := replaceFromTemporary(directory, temporary, target); err != nil {
		_ = removeExact(directory, temporary)
		return err
	}
	return nil
}

func removeExact(directory *os.File, name string) error {
	return os.Remove(descriptorPath(directory, name))
}

func syncDirectory(directory *os.File) error {
	return syscall.Fsync(int(directory.Fd()))
}

func ensureRootIdentity(root *os.File, expected fileIdentity) error {
	actual, err := identityFromOpenFile(root)
	if err != nil {
		return err
	}
	if !sameKernelObject(expected, actual) {
		return errors.New("media root was substituted during the transaction")
	}
	return nil
}

func removeTemporary(items []temporaryFile, directory *os.File, name string) []temporaryFile {
	result := items[:0]
	for _, item := range items {
		if item.directory == directory && item.name == name {
			continue
		}
		result = append(result, item)
	}
	return result
}

func rollbackInstall(root, boot *os.File, original []byte, originalMode uint32, state *installMutationState) error {
	var failures []error
	for _, temporary := range state.temporary {
		if err := removeExact(temporary.directory, temporary.name); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if state.manifestPublished {
		if err := removeExact(root, ManifestName); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if state.wrapperReplaced {
		if err := atomicReplace(boot, arm64FallbackName, original, originalMode); err != nil {
			failures = append(failures, err)
		}
	}
	if state.backupPublished {
		if err := removeExact(boot, arm64OriginalName); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if err := syncDirectory(boot); err != nil {
		failures = append(failures, err)
	}
	if err := syncDirectory(root); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func restoreInstalledState(root, boot *os.File, wrapper, original []byte, originalMode uint32, manifest []byte) error {
	var failures []error
	if err := atomicReplace(boot, arm64FallbackName, wrapper, 0o644); err != nil {
		failures = append(failures, err)
	}
	if err := atomicReplace(boot, arm64OriginalName, original, originalMode); err != nil {
		failures = append(failures, err)
	}
	if err := atomicReplace(root, ManifestName, manifest, 0o644); err != nil {
		failures = append(failures, err)
	}
	if err := syncDirectory(boot); err != nil {
		failures = append(failures, err)
	}
	if err := syncDirectory(root); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func generateFromOpenRoot(ctx context.Context, root *os.File, rootIdentity fileIdentity, maxFiles int) (Manifest, error) {
	scan, err := reopenDirectory(root)
	if err != nil {
		return Manifest{}, err
	}
	defer scan.Close()
	if maxFiles <= 0 {
		maxFiles = DefaultMaximumFiles
	}
	if maxFiles > MaximumManifestLines {
		return Manifest{}, fmt.Errorf("file limit %d exceeds the %d-file safety maximum", maxFiles, MaximumManifestLines)
	}
	var entries []treeEntry
	var total uint64
	manifestCount := 0
	if err := enumerateDirectory(ctx, scan, "", maxFiles, nil, &entries, &total, &manifestCount); err != nil {
		return Manifest{}, err
	}
	if manifestCount != 0 {
		return Manifest{}, errors.New("runtime-integrity manifest already exists")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relative < entries[j].relative })
	hashed, err := hashEntries(ctx, scan, rootIdentity, entries, total, Options{MaxFiles: maxFiles}, nil)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{TotalBytes: total, Entries: make([]Entry, 0, len(hashed))}
	for _, entry := range hashed {
		manifest.Entries = append(manifest.Entries, entry.Entry)
	}
	return manifest, nil
}

func verifyFromOpenRoot(ctx context.Context, root *os.File, rootIdentity fileIdentity, maxFiles int) (VerificationResult, error) {
	currentRoot, err := identityFromOpenFile(root)
	if err != nil {
		return VerificationResult{}, err
	}
	if !sameKernelObject(rootIdentity, currentRoot) {
		return VerificationResult{}, errors.New("media root was substituted before verification")
	}
	rootIdentity = currentRoot
	scan, err := reopenDirectory(root)
	if err != nil {
		return VerificationResult{}, err
	}
	defer scan.Close()
	if maxFiles <= 0 {
		maxFiles = DefaultMaximumFiles
	}
	var entries []treeEntry
	var total uint64
	manifestCount := 0
	if err := enumerateDirectory(ctx, scan, "", maxFiles, nil, &entries, &total, &manifestCount); err != nil {
		return VerificationResult{}, err
	}
	if manifestCount != 1 {
		return VerificationResult{}, errors.New("installed media must contain exactly one root md5sum.txt")
	}
	manifestData, err := readManifest(scan)
	if err != nil {
		return VerificationResult{}, err
	}
	manifest, err := Parse(manifestData)
	if err != nil {
		return VerificationResult{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relative < entries[j].relative })
	hashed, err := hashEntries(ctx, scan, rootIdentity, entries, total, Options{MaxFiles: maxFiles}, nil)
	if err != nil {
		return VerificationResult{}, err
	}
	actual := make(map[string]hashedEntry, len(hashed))
	for _, entry := range hashed {
		actual[strings.ToLower(entry.Path)] = entry
	}
	result := VerificationResult{Root: root.Name(), ManifestPath: filepath.Join(root.Name(), ManifestName), DeclaredTotalBytes: manifest.TotalBytes, ActualTotalBytes: total}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, expected := range manifest.Entries {
		key := strings.ToLower(expected.Path)
		seen[key] = struct{}{}
		fileResult := VerificationFile{Path: expected.Path, ExpectedMD5: expected.MD5, Status: "missing"}
		current, exists := actual[key]
		if !exists {
			fileResult.Error = "file is missing"
			result.Errors = append(result.Errors, expected.Path+": file is missing")
			result.Files = append(result.Files, fileResult)
			continue
		}
		fileResult.ActualMD5 = current.MD5
		fileResult.Size = current.Size
		if current.MD5 != expected.MD5 {
			fileResult.Status = "changed"
			fileResult.Error = "MD5 digest does not match"
			result.Errors = append(result.Errors, expected.Path+": MD5 digest does not match")
		} else {
			fileResult.Status = "ok"
		}
		result.Files = append(result.Files, fileResult)
	}
	for _, current := range hashed {
		if _, exists := seen[strings.ToLower(current.Path)]; exists {
			continue
		}
		result.Unexpected = append(result.Unexpected, current.Path)
		result.Errors = append(result.Errors, current.Path+": unexpected file is not covered by the manifest")
	}
	if manifest.TotalBytes != total {
		result.Errors = append(result.Errors, fmt.Sprintf("md5sum_totalbytes is 0x%x but the covered media tree totals 0x%x", manifest.TotalBytes, total))
	}
	result.Valid = len(result.Errors) == 0
	return result, nil
}
