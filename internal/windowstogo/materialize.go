//go:build linux

package windowstogo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/secureboot"
)

const (
	maxBootTreeEntries = 4096
	maxBootTreeBytes   = uint64(512 * 1024 * 1024)
	copyBufferBytes    = 4 * 1024 * 1024
)

type MaterializationEvidence struct {
	BootFiles                     int         `json:"boot_files"`
	BootBytes                     uint64      `json:"boot_bytes"`
	BootManagerSHA256             string      `json:"boot_manager_sha256"`
	FallbackSHA256                string      `json:"fallback_sha256"`
	BootManagerAuthenticodeSHA256 string      `json:"boot_manager_authenticode_sha256"`
	FallbackAuthenticodeSHA256    string      `json:"fallback_authenticode_sha256"`
	OfflinePolicySHA256           string      `json:"offline_policy_sha256"`
	AnswerFileSHA256              string      `json:"answer_file_sha256"`
	AnswerFileBytes               uint64      `json:"answer_file_bytes"`
	BCD                           BCDEvidence `json:"bcd"`
}

func Materialize(ctx context.Context, osRoot, espRoot string, plan Plan, layout GPTLayout) (MaterializationEvidence, error) {
	if ctx == nil {
		return MaterializationEvidence{}, errors.New("windows To Go materialization context is nil")
	}
	if err := ValidatePlan(plan); err != nil {
		return MaterializationEvidence{}, err
	}
	if err := ValidateGPT(layout, plan); err != nil {
		return MaterializationEvidence{}, err
	}
	for label, root := range map[string]string{"Windows": osRoot, "ESP": espRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return MaterializationEvidence{}, fmt.Errorf("%s mount root must be canonical and absolute", label)
		}
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return MaterializationEvidence{}, fmt.Errorf("%s mount root is not a real directory", label)
		}
	}

	efiSource, err := findCaseInsensitive(osRoot, "Windows/Boot/EFI")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	fontsSource, err := findCaseInsensitive(osRoot, "Windows/Boot/Fonts")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	template, err := findCaseInsensitive(osRoot, "Windows/System32/config/BCD-Template")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	windowsRoot, err := findCaseInsensitive(osRoot, "Windows")
	if err != nil {
		return MaterializationEvidence{}, err
	}

	efiDir, err := ensureRealDirectory(espRoot, "EFI")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	microsoftDir, err := ensureRealDirectory(efiDir, "Microsoft")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	bootDir, err := ensureRealDirectory(microsoftDir, "Boot")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	if err := requireEmptyDirectory(bootDir); err != nil {
		return MaterializationEvidence{}, err
	}

	files, bytesCopied, err := copyTreeBounded(ctx, efiSource, bootDir)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("copy Windows EFI boot tree: %w", err)
	}
	fontsDir, err := ensureRealDirectory(bootDir, "Fonts")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	fontFiles, fontBytes, err := copyTreeBounded(ctx, fontsSource, fontsDir)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("copy Windows EFI fonts: %w", err)
	}
	files += fontFiles
	bytesCopied += fontBytes
	if bytesCopied > maxBootTreeBytes || files > maxBootTreeEntries {
		return MaterializationEvidence{}, errors.New("windows EFI boot material exceeds the bounded copy limits")
	}

	bootManager, err := findCaseInsensitive(bootDir, "bootmgfw.efi")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	fallbackDir, err := ensureRealDirectory(efiDir, "Boot")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	fallback := filepath.Join(fallbackDir, "bootaa64.efi")
	if err := ensureNoCaseInsensitiveEntry(fallbackDir, filepath.Base(fallback)); err != nil {
		return MaterializationEvidence{}, err
	}
	fallbackBytes, fallbackHash, err := copyFileExact(ctx, bootManager, fallback)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("create ARM64 UEFI fallback loader: %w", err)
	}
	files++
	bytesCopied += fallbackBytes
	bootRawHash, err := hashFile(bootManager)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("hash installed Windows boot manager: %w", err)
	}
	bootPE, err := secureboot.AuthenticodeSHA256File(bootManager)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("inspect installed Windows boot manager: %w", err)
	}
	fallbackPE, err := secureboot.AuthenticodeSHA256File(fallback)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("inspect installed ARM64 fallback loader: %w", err)
	}
	if bootPE.Machine != secureboot.MachineARM64 || fallbackPE.Machine != secureboot.MachineARM64 || bootPE.SHA256 != fallbackPE.SHA256 || fallbackHash != bootRawHash {
		return MaterializationEvidence{}, errors.New("installed UEFI boot manager and ARM64 fallback loader do not match")
	}

	if len(layout.Partitions) != 2 {
		return MaterializationEvidence{}, errors.New("windows To Go GPT does not expose two partitions for BCD binding")
	}
	bcdPath := filepath.Join(bootDir, "BCD")
	if err := ensureNoCaseInsensitiveEntry(bootDir, "BCD"); err != nil {
		return MaterializationEvidence{}, err
	}
	bcd, err := CreateBCD(ctx, BCDOptions{
		TemplatePath: template,
		OutputPath:   bcdPath,
		DiskGUID:     layout.DiskGUID,
		ESPGUID:      layout.Partitions[0].UniqueGUID,
		OSGUID:       layout.Partitions[1].UniqueGUID,
		Locale:       plan.Image.DefaultLanguage,
		Description:  "Windows 11",
	})
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("create Windows To Go BCD store: %w", err)
	}

	panther, err := ensureRealDirectory(windowsRoot, "Panther")
	if err != nil {
		return MaterializationEvidence{}, err
	}
	if err := ensureNoCaseInsensitiveEntry(panther, "unattend.xml"); err != nil {
		return MaterializationEvidence{}, fmt.Errorf("refuse to replace existing Windows answer file: %w", err)
	}
	answerFile, err := WindowsToGoAnswerFile(plan.Customizations)
	if err != nil {
		return MaterializationEvidence{}, err
	}
	answerDigest := sha256.Sum256(answerFile)
	answerHash := hex.EncodeToString(answerDigest[:])
	if uint64(len(answerFile)) != plan.AnswerFileBytes || answerHash != plan.AnswerFileSHA256 {
		return MaterializationEvidence{}, errors.New("Windows To Go answer file changed after planning")
	}
	answerPath := filepath.Join(panther, "unattend.xml")
	writtenHash, err := writeFileExact(answerPath, answerFile)
	if err != nil {
		return MaterializationEvidence{}, fmt.Errorf("write Windows To Go answer file: %w", err)
	}

	return MaterializationEvidence{
		BootFiles: files, BootBytes: bytesCopied,
		BootManagerSHA256: bootRawHash, FallbackSHA256: fallbackHash,
		BootManagerAuthenticodeSHA256: bootPE.SHA256, FallbackAuthenticodeSHA256: fallbackPE.SHA256,
		OfflinePolicySHA256: writtenHash,
		AnswerFileSHA256:    writtenHash,
		AnswerFileBytes:     uint64(len(answerFile)),
		BCD:                 bcd,
	}, nil
}

func ensureRealDirectory(parent, name string) (string, error) {
	if strings.TrimSpace(name) != name || name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid directory name %q", name)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	var match os.DirEntry
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), name) {
			if match != nil {
				return "", fmt.Errorf("ambiguous case-insensitive directory %q below %s", name, parent)
			}
			match = entry
		}
	}
	if match == nil {
		path := filepath.Join(parent, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", err
		}
		return path, nil
	}
	if match.Type()&os.ModeSymlink != 0 || !match.IsDir() {
		return "", fmt.Errorf("%s is not a real directory", filepath.Join(parent, match.Name()))
	}
	return filepath.Join(parent, match.Name()), nil
}

func requireEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("boot destination %s is not empty", path)
	}
	return nil
}

func ensureNoCaseInsensitiveEntry(parent, name string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), name) {
			return fmt.Errorf("%s already exists", filepath.Join(parent, entry.Name()))
		}
	}
	return nil
}

func copyTreeBounded(ctx context.Context, sourceRoot, destinationRoot string) (int, uint64, error) {
	seen := make(map[string]string)
	files := 0
	var total uint64
	err := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link in Windows boot tree: %s", filepath.ToSlash(relative))
		}
		key := strings.ToLower(filepath.ToSlash(relative))
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("case-insensitive collision in Windows boot tree: %s and %s", previous, filepath.ToSlash(relative))
		}
		seen[key] = filepath.ToSlash(relative)
		destination := filepath.Join(destinationRoot, relative)
		if entry.IsDir() {
			return os.Mkdir(destination, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular Windows boot file: %s", filepath.ToSlash(relative))
		}
		files++
		if files > maxBootTreeEntries {
			return errors.New("windows boot tree exceeds the file-count limit")
		}
		size, _, err := copyFileExact(ctx, path, destination)
		if err != nil {
			return err
		}
		if size > maxBootTreeBytes-total {
			return errors.New("windows boot tree exceeds the byte limit")
		}
		total += size
		return nil
	})
	return files, total, err
}

func copyFileExact(ctx context.Context, sourcePath, destinationPath string) (uint64, string, error) {
	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, "", err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return 0, "", errors.New("boot source is not a non-empty regular file")
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(destination, hash), &contextReader{ctx: ctx, reader: source}, make([]byte, copyBufferBytes))
	if copyErr == nil && written != info.Size() {
		copyErr = io.ErrShortWrite
	}
	if copyErr == nil {
		copyErr = destination.Sync()
	}
	closeErr := destination.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(destinationPath)
		return 0, "", copyErr
	}
	expected := hex.EncodeToString(hash.Sum(nil))
	actual, err := hashFile(destinationPath)
	if err != nil {
		return 0, "", err
	}
	if actual != expected {
		return 0, "", errors.New("copied boot file SHA-256 mismatch")
	}
	return uint64(written), actual, nil
}

func writeFileExact(path string, data []byte) (string, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(path)
		return "", writeErr
	}
	hash, err := hashFile(path)
	if err != nil {
		return "", err
	}
	expected := sha256.Sum256(data)
	if hash != hex.EncodeToString(expected[:]) {
		return "", errors.New("written file SHA-256 mismatch")
	}
	return hash, nil
}

func hashFile(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, copyBufferBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, context.Cause(reader.ctx)
	}
	return reader.reader.Read(buffer)
}

func VerifyMaterialization(ctx context.Context, osRoot, espRoot string, plan Plan, layout GPTLayout, expected MaterializationEvidence) error {
	if ctx == nil {
		return errors.New("windows To Go verification context is nil")
	}
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if err := ValidateGPT(layout, plan); err != nil {
		return err
	}
	efiSource, err := findCaseInsensitive(osRoot, "Windows/Boot/EFI")
	if err != nil {
		return err
	}
	fontsSource, err := findCaseInsensitive(osRoot, "Windows/Boot/Fonts")
	if err != nil {
		return err
	}
	template, err := findCaseInsensitive(osRoot, "Windows/System32/config/BCD-Template")
	if err != nil {
		return err
	}
	bootDir, err := findCaseInsensitive(espRoot, "EFI/Microsoft/Boot")
	if err != nil {
		return err
	}
	fontsDir, err := findCaseInsensitive(bootDir, "Fonts")
	if err != nil {
		return err
	}
	files, bytesVerified, err := compareTreeBounded(ctx, efiSource, bootDir)
	if err != nil {
		return fmt.Errorf("verify Windows EFI boot tree: %w", err)
	}
	fontFiles, fontBytes, err := compareTreeBounded(ctx, fontsSource, fontsDir)
	if err != nil {
		return fmt.Errorf("verify Windows EFI fonts: %w", err)
	}
	files += fontFiles
	bytesVerified += fontBytes
	bootManager, err := findCaseInsensitive(bootDir, "bootmgfw.efi")
	if err != nil {
		return err
	}
	fallback, err := findCaseInsensitive(espRoot, "EFI/Boot/bootaa64.efi")
	if err != nil {
		return err
	}
	bootHash, err := hashFile(bootManager)
	if err != nil {
		return err
	}
	fallbackHash, err := hashFile(fallback)
	if err != nil {
		return err
	}
	fallbackInfo, err := os.Stat(fallback)
	if err != nil {
		return err
	}
	files++
	bytesVerified += uint64(fallbackInfo.Size())
	bootPE, err := secureboot.AuthenticodeSHA256File(bootManager)
	if err != nil {
		return err
	}
	fallbackPE, err := secureboot.AuthenticodeSHA256File(fallback)
	if err != nil {
		return err
	}
	if bootPE.Machine != secureboot.MachineARM64 || fallbackPE.Machine != secureboot.MachineARM64 ||
		bootPE.SHA256 != fallbackPE.SHA256 || bootHash != fallbackHash {
		return errors.New("read-back ARM64 boot manager and fallback loader do not match")
	}
	if expected.BootFiles != files || expected.BootBytes != bytesVerified ||
		expected.BootManagerSHA256 != bootHash || expected.FallbackSHA256 != fallbackHash ||
		expected.BootManagerAuthenticodeSHA256 != bootPE.SHA256 || expected.FallbackAuthenticodeSHA256 != fallbackPE.SHA256 {
		return errors.New("read-back Windows boot-tree evidence does not match the completed write")
	}

	policyPath, err := findCaseInsensitive(osRoot, "Windows/Panther/unattend.xml")
	if err != nil {
		return err
	}
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	expectedAnswer, err := WindowsToGoAnswerFile(plan.Customizations)
	if err != nil {
		return err
	}
	if string(policy) != string(expectedAnswer) {
		return errors.New("read-back Windows To Go answer file differs from the reviewed bytes")
	}
	answerHash, err := hashFile(policyPath)
	if err != nil {
		return err
	}
	if uint64(len(policy)) != expected.AnswerFileBytes || expected.AnswerFileBytes != plan.AnswerFileBytes ||
		answerHash != expected.AnswerFileSHA256 || answerHash != expected.OfflinePolicySHA256 || answerHash != plan.AnswerFileSHA256 {
		return errors.New("read-back Windows To Go answer-file evidence mismatch")
	}

	bcdPath, err := findCaseInsensitive(bootDir, "BCD")
	if err != nil {
		return err
	}
	bcd, err := VerifyBCD(ctx, BCDOptions{
		TemplatePath: template,
		OutputPath:   bcdPath,
		DiskGUID:     layout.DiskGUID,
		ESPGUID:      layout.Partitions[0].UniqueGUID,
		OSGUID:       layout.Partitions[1].UniqueGUID,
		Locale:       plan.Image.DefaultLanguage,
		Description:  "Windows 11",
	})
	if err != nil {
		return err
	}
	if bcd != expected.BCD {
		return errors.New("read-back BCD evidence does not match the completed transaction")
	}
	return nil
}

func compareTreeBounded(ctx context.Context, sourceRoot, destinationRoot string) (int, uint64, error) {
	files := 0
	var total uint64
	err := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil || relative == "." {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link in source boot tree: %s", filepath.ToSlash(relative))
		}
		destination := filepath.Join(destinationRoot, relative)
		if entry.IsDir() {
			info, err := os.Lstat(destination)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("missing or unsafe destination directory %s", filepath.ToSlash(relative))
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe source boot file %s", filepath.ToSlash(relative))
		}
		sourceHash, err := hashFile(path)
		if err != nil {
			return err
		}
		destinationHash, err := hashFile(destination)
		if err != nil {
			return err
		}
		if sourceHash != destinationHash {
			return fmt.Errorf("boot file %s SHA-256 mismatch", filepath.ToSlash(relative))
		}
		files++
		if files > maxBootTreeEntries || uint64(info.Size()) > maxBootTreeBytes-total {
			return errors.New("verified boot tree exceeds its bounded limits")
		}
		total += uint64(info.Size())
		return nil
	})
	return files, total, err
}
