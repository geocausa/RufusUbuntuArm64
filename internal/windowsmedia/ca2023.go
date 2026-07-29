//go:build linux

package windowsmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const (
	windowsCA2023EFIPath      = "/Windows/Boot/EFI_EX"
	windowsCA2023FontsPath    = "/Windows/Boot/Fonts_EX"
	windowsCA2023BootmgfwPath = "/Windows/Boot/EFI_EX/bootmgfw_EX.efi"
	windowsCA2023BootmgrPath  = "/Windows/Boot/EFI_EX/bootmgr_EX.efi"
	maxWindowsCA2023Assets    = 512
	maxWindowsCA2023Bytes     = uint64(128 * 1024 * 1024)
)

// WindowsCA2023Capability is read-only evidence that one boot.wim image carries
// the complete Rufus-compatible Windows UEFI CA 2023 replacement set.
type WindowsCA2023Capability struct {
	Available        bool   `json:"available"`
	ImageIndex       int    `json:"image_index,omitempty"`
	Architecture     string `json:"architecture,omitempty"`
	AssetCount       int    `json:"asset_count,omitempty"`
	ReplacementBytes uint64 `json:"replacement_bytes,omitempty"`
	OriginalBytes    uint64 `json:"original_bytes,omitempty"`
	ManifestSHA256   string `json:"manifest_sha256,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// WindowsCA2023Asset binds one staged, hashed source file to one exact relative
// path on the completed removable-media filesystem.
type WindowsCA2023Asset struct {
	Destination string `json:"destination"`
	Size        uint64 `json:"size"`
	SHA256      string `json:"sha256"`
	sourcePath  string
}

// WindowsCA2023Plan is the immutable pre-erasure replacement evidence.
type WindowsCA2023Plan struct {
	ImageIndex       int                  `json:"image_index"`
	Architecture     string               `json:"architecture"`
	Assets           []WindowsCA2023Asset `json:"assets"`
	ReplacementBytes uint64               `json:"replacement_bytes"`
	OriginalBytes    uint64               `json:"original_bytes"`
	ManifestSHA256   string               `json:"manifest_sha256"`
	replacements     map[string]struct{}
}

type windowsCA2023PEEvidence struct {
	Machine                          uint16
	AuthenticodeSHA256               string
	WindowsCA2023CertificateEvidence bool
}

var (
	inspectWindowsCA2023Metadata = InspectWIMMetadata
	inspectWindowsCA2023WIMPath  = inspectWIMPath
	windowsCA2023WIMExecutable   = wimlibExecutable
	extractWindowsCA2023Paths    = extractWindowsCA2023
	inspectWindowsCA2023PE       = inspectCA2023PE
)

func resolveWindowsCA2023Root(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("Windows CA 2023 ISO root is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("Windows CA 2023 ISO root is not a directory")
	}
	return resolved, nil
}

func validateWindowsCA2023Selection(metadata windowsconfig.MediaMetadata, capability WindowsCA2023Capability, targetSystem, filesystem string) error {
	profile := windowsconfig.Capabilities(metadata)
	if !profile.Recognized || profile.Generation != "11" || profile.Family != "client" {
		reason := strings.TrimSpace(profile.Reason)
		if reason == "" {
			reason = "available only for positively identified Windows 11 client media"
		}
		return fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)
	}
	if !capability.Available {
		reason := strings.TrimSpace(capability.Reason)
		if reason == "" {
			reason = "a complete boot.wim _EX replacement set was not proven"
		}
		return fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)
	}
	installArchitecture := normalizeWIMArchitecture(metadata.Architecture)
	if installArchitecture == "" || capability.Architecture == "" {
		return errors.New("Windows UEFI CA 2023 architecture evidence is missing or unsupported")
	}
	if installArchitecture != capability.Architecture {
		return fmt.Errorf("Windows installation payload architecture %s does not match boot.wim CA 2023 architecture %s", installArchitecture, capability.Architecture)
	}
	if strings.ToLower(strings.TrimSpace(targetSystem)) != "uefi" {
		return errors.New("Windows UEFI CA 2023 bootloader replacement requires a resolved UEFI target")
	}
	if strings.ToLower(strings.TrimSpace(filesystem)) != "fat32" {
		return errors.New("Windows UEFI CA 2023 bootloader replacement currently requires FAT32; the pinned UEFI:NTFS first-stage image carries embedded certificate-chain evidence identifying Microsoft UEFI CA 2011 and cannot be represented as CA 2023-only media")
	}
	return nil
}

func validateWindowsCA2023Architecture(metadata windowsconfig.MediaMetadata, plan *WindowsCA2023Plan) error {
	if plan == nil {
		return errors.New("Windows UEFI CA 2023 replacement plan is missing")
	}
	installArchitecture := normalizeWIMArchitecture(metadata.Architecture)
	if installArchitecture == "" {
		return errors.New("Windows installation payload architecture is missing or unsupported")
	}
	if installArchitecture != plan.Architecture {
		return fmt.Errorf("Windows installation payload architecture %s does not match staged boot.wim CA 2023 architecture %s", installArchitecture, plan.Architecture)
	}
	return nil
}

func summarizeWindowsCA2023Capability(capability WindowsCA2023Capability, plan *WindowsCA2023Plan) WindowsCA2023Capability {
	if plan == nil {
		return capability
	}
	capability.Available = true
	capability.ImageIndex = plan.ImageIndex
	capability.Architecture = plan.Architecture
	capability.AssetCount = len(plan.Assets)
	capability.ReplacementBytes = plan.ReplacementBytes
	capability.OriginalBytes = plan.OriginalBytes
	capability.ManifestSHA256 = plan.ManifestSHA256
	capability.Reason = ""
	return capability
}

// InspectWindowsCA2023Capability checks only the two boot.wim indexes used by
// Windows Setup. Index 2 is preferred, matching upstream Rufus; index 1 is the
// bounded fallback for unofficial single-index media.
func InspectWindowsCA2023Capability(ctx context.Context, bootWIMPath string) (WindowsCA2023Capability, error) {
	if ctx == nil {
		return WindowsCA2023Capability{}, errors.New("Windows CA 2023 capability context is nil")
	}
	if strings.TrimSpace(bootWIMPath) == "" {
		return WindowsCA2023Capability{}, errors.New("Windows CA 2023 boot.wim path is empty")
	}
	metadata, err := inspectWindowsCA2023Metadata(ctx, bootWIMPath)
	if err != nil {
		return WindowsCA2023Capability{}, fmt.Errorf("inspect boot.wim metadata: %w", err)
	}
	bootArchitecture := normalizeWIMArchitecture(metadata.Architecture)
	if bootArchitecture == "" {
		return WindowsCA2023Capability{Reason: "boot.wim architecture is missing or unsupported"}, nil
	}
	indexes := make([]int, 0, 2)
	if metadata.ImageCount >= 2 {
		indexes = append(indexes, 2)
	}
	if metadata.ImageCount >= 1 {
		indexes = append(indexes, 1)
	}
	if len(indexes) == 0 {
		return WindowsCA2023Capability{Reason: "boot.wim contains no usable Windows Setup image"}, nil
	}
	executable, err := windowsCA2023WIMExecutable()
	if err != nil {
		return WindowsCA2023Capability{}, err
	}
	for _, index := range indexes {
		complete := true
		for _, path := range []string{windowsCA2023BootmgfwPath, windowsCA2023BootmgrPath, windowsCA2023FontsPath} {
			available, pathErr := inspectWindowsCA2023WIMPath(ctx, executable, bootWIMPath, index, path)
			if pathErr != nil {
				return WindowsCA2023Capability{}, fmt.Errorf("inspect boot.wim image %d path %s: %w", index, path, pathErr)
			}
			if !available {
				complete = false
				break
			}
		}
		if complete {
			return WindowsCA2023Capability{Available: true, ImageIndex: index, Architecture: bootArchitecture}, nil
		}
	}
	return WindowsCA2023Capability{Reason: "boot.wim does not contain a complete Windows/Boot/EFI_EX and Windows/Boot/Fonts_EX replacement set in Setup index 2 or fallback index 1"}, nil
}

// StageWindowsCA2023 extracts, validates, hashes, and capacity-binds the exact
// replacement set before the destructive boundary. The caller owns workRoot.
func StageWindowsCA2023(ctx context.Context, bootWIMPath, isoRoot, workRoot string, capability WindowsCA2023Capability) (*WindowsCA2023Plan, error) {
	if ctx == nil {
		return nil, errors.New("Windows CA 2023 staging context is nil")
	}
	if !capability.Available || (capability.ImageIndex != 1 && capability.ImageIndex != 2) {
		reason := strings.TrimSpace(capability.Reason)
		if reason == "" {
			reason = "complete CA 2023 boot assets were not proven"
		}
		return nil, fmt.Errorf("Windows CA 2023 bootloaders are unavailable: %s", reason)
	}
	isoRoot, err := resolveWindowsCA2023Root(isoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve Windows ISO root for CA 2023 staging: %w", err)
	}
	stageRoot, err := os.MkdirTemp(workRoot, "rufusarm64-windows-ca2023-")
	if err != nil {
		return nil, fmt.Errorf("create Windows CA 2023 staging directory: %w", err)
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("secure Windows CA 2023 staging directory: %w", err)
	}
	if err := extractWindowsCA2023Paths(ctx, bootWIMPath, capability.ImageIndex, stageRoot); err != nil {
		return nil, err
	}

	efiRoot := filepath.Join(stageRoot, "Windows", "Boot", "EFI_EX")
	fontsRoot := filepath.Join(stageRoot, "Windows", "Boot", "Fonts_EX")
	bootmgfw := filepath.Join(efiRoot, "bootmgfw_EX.efi")
	bootmgr := filepath.Join(efiRoot, "bootmgr_EX.efi")
	bootmgfwEvidence, err := inspectWindowsCA2023PE(bootmgfw)
	if err != nil {
		return nil, fmt.Errorf("inspect staged CA 2023 bootmgfw_EX.efi: %w", err)
	}
	bootmgrEvidence, err := inspectWindowsCA2023PE(bootmgr)
	if err != nil {
		return nil, fmt.Errorf("inspect staged CA 2023 bootmgr_EX.efi: %w", err)
	}
	if !bootmgfwEvidence.WindowsCA2023CertificateEvidence || !bootmgrEvidence.WindowsCA2023CertificateEvidence {
		return nil, errors.New("staged _EX bootloaders do not both carry embedded certificate-chain evidence identifying Windows UEFI CA 2023")
	}
	if bootmgfwEvidence.Machine != bootmgrEvidence.Machine {
		return nil, fmt.Errorf("staged CA 2023 bootloader architectures disagree: bootmgfw=0x%x bootmgr=0x%x", bootmgfwEvidence.Machine, bootmgrEvidence.Machine)
	}
	architecture, fallback, err := ca2023Architecture(bootmgfwEvidence.Machine)
	if err != nil {
		return nil, err
	}
	if capability.Architecture == "" || capability.Architecture != architecture {
		return nil, fmt.Errorf("boot.wim metadata architecture %s does not match staged CA 2023 PE architecture %s", capability.Architecture, architecture)
	}
	if _, ok := findRelativeCaseInsensitive(isoRoot, fallback); !ok {
		return nil, fmt.Errorf("the ISO has no %s fallback loader for the staged %s CA 2023 bootloader", filepath.ToSlash(fallback), architecture)
	}
	if _, ok := findRelativeCaseInsensitive(isoRoot, "bootmgr.efi"); !ok {
		return nil, errors.New("the ISO has no root bootmgr.efi to replace with the expected CA 2023 bootmgr_EX.efi")
	}

	plan := &WindowsCA2023Plan{
		ImageIndex:   capability.ImageIndex,
		Architecture: architecture,
		replacements: make(map[string]struct{}),
	}
	if err := addWindowsCA2023Asset(plan, isoRoot, bootmgfw, fallback, true); err != nil {
		return nil, err
	}
	if err := addWindowsCA2023Asset(plan, isoRoot, bootmgr, "bootmgr.efi", true); err != nil {
		return nil, err
	}
	entryCount := 0
	err = filepath.WalkDir(fontsRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("CA 2023 font staging contains a symbolic link: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		entryCount++
		if entryCount > maxWindowsCA2023Assets-2 {
			return fmt.Errorf("CA 2023 font set exceeds the %d-file safety limit", maxWindowsCA2023Assets-2)
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("CA 2023 font staging contains a non-regular file: %s", path)
		}
		relative, relErr := filepath.Rel(fontsRoot, path)
		if relErr != nil {
			return relErr
		}
		destination := filepath.Join("EFI", "Microsoft", "Boot", "Fonts", relative)
		return addWindowsCA2023Asset(plan, isoRoot, path, destination, false)
	})
	if err != nil {
		return nil, fmt.Errorf("inspect staged CA 2023 fonts: %w", err)
	}
	if entryCount == 0 {
		return nil, errors.New("staged Windows/Boot/Fonts_EX directory contains no files")
	}
	if plan.ReplacementBytes > maxWindowsCA2023Bytes {
		return nil, fmt.Errorf("CA 2023 replacement set is %d bytes; the safety limit is %d", plan.ReplacementBytes, maxWindowsCA2023Bytes)
	}
	sort.Slice(plan.Assets, func(i, j int) bool {
		return strings.ToLower(filepath.ToSlash(plan.Assets[i].Destination)) < strings.ToLower(filepath.ToSlash(plan.Assets[j].Destination))
	})
	manifest := sha256.New()
	for _, asset := range plan.Assets {
		fmt.Fprintf(manifest, "%s\x00%d\x00%s\n", strings.ToLower(filepath.ToSlash(asset.Destination)), asset.Size, asset.SHA256)
	}
	plan.ManifestSHA256 = hex.EncodeToString(manifest.Sum(nil))
	return plan, nil
}

func extractWindowsCA2023(ctx context.Context, bootWIMPath string, imageIndex int, destination string) error {
	wimlib, err := wimlibExecutable()
	if err != nil {
		return err
	}
	stdout := NewBoundedBuffer(2 * 1024 * 1024)
	stderr := NewBoundedBuffer(256 * 1024)
	command := exec.CommandContext(ctx, wimlib, "extract", bootWIMPath, strconv.Itoa(imageIndex), windowsCA2023EFIPath, windowsCA2023FontsPath, "--dest-dir="+destination, "--preserve-dir-structure")
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("extract Windows CA 2023 boot assets: %w: %s", err, strings.TrimSpace(stderr.String()+"\n"+stdout.String()))
	}
	return nil
}

func inspectCA2023PE(path string) (windowsCA2023PEEvidence, error) {
	hash, err := secureboot.AuthenticodeSHA256File(path)
	if err != nil {
		return windowsCA2023PEEvidence{}, err
	}
	certificates, err := secureboot.EmbeddedAuthenticodeCertificates(path)
	if err != nil {
		return windowsCA2023PEEvidence{}, err
	}
	ca2023 := false
	for _, certificate := range certificates {
		identity := certificate.Subject.String() + "\n" + certificate.Issuer.String()
		if strings.Contains(strings.ToLower(identity), "windows uefi ca 2023") {
			ca2023 = true
			break
		}
	}
	return windowsCA2023PEEvidence{Machine: hash.Machine, AuthenticodeSHA256: hash.SHA256, WindowsCA2023CertificateEvidence: ca2023}, nil
}

func ca2023Architecture(machine uint16) (string, string, error) {
	switch machine {
	case 0xaa64:
		return "arm64", filepath.Join("EFI", "BOOT", "BOOTAA64.EFI"), nil
	case 0x8664:
		return "amd64", filepath.Join("EFI", "BOOT", "BOOTX64.EFI"), nil
	case 0x014c:
		return "x86", filepath.Join("EFI", "BOOT", "BOOTIA32.EFI"), nil
	default:
		return "", "", fmt.Errorf("staged CA 2023 bootloader machine 0x%x is unsupported", machine)
	}
}

func addWindowsCA2023Asset(plan *WindowsCA2023Plan, isoRoot, sourcePath, destination string, requireOriginal bool) error {
	if plan == nil {
		return errors.New("Windows CA 2023 plan is nil")
	}
	clean, err := cleanCA2023Destination(destination)
	if err != nil {
		return err
	}
	key := strings.ToLower(filepath.ToSlash(clean))
	if _, exists := plan.replacements[key]; exists {
		return fmt.Errorf("duplicate Windows CA 2023 destination %s", filepath.ToSlash(clean))
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat staged CA 2023 asset %s: %w", sourcePath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("staged CA 2023 asset is not a regular file: %s", sourcePath)
	}
	digest, err := fileSHA256(sourcePath)
	if err != nil {
		return fmt.Errorf("hash staged CA 2023 asset %s: %w", sourcePath, err)
	}
	assetSize := uint64(info.Size())
	plan.ReplacementBytes, err = checkedAdd("Windows CA 2023 replacement total", plan.ReplacementBytes, assetSize)
	if err != nil {
		return err
	}
	if original, ok := findRelativeCaseInsensitive(isoRoot, clean); ok {
		originalInfo, statErr := os.Lstat(original)
		if statErr != nil {
			return statErr
		}
		if !originalInfo.Mode().IsRegular() {
			return fmt.Errorf("CA 2023 destination in the ISO is not a regular file: %s", filepath.ToSlash(clean))
		}
		plan.OriginalBytes, err = checkedAdd("Windows CA 2023 original total", plan.OriginalBytes, uint64(originalInfo.Size()))
		if err != nil {
			return err
		}
	} else if requireOriginal {
		return fmt.Errorf("required CA 2023 replacement destination is missing from the ISO: %s", filepath.ToSlash(clean))
	}
	plan.replacements[key] = struct{}{}
	plan.Assets = append(plan.Assets, WindowsCA2023Asset{
		Destination: filepath.ToSlash(clean),
		Size:        assetSize,
		SHA256:      hex.EncodeToString(digest[:]),
		sourcePath:  sourcePath,
	})
	if len(plan.Assets) > maxWindowsCA2023Assets {
		return fmt.Errorf("CA 2023 replacement set exceeds the %d-file safety limit", maxWindowsCA2023Assets)
	}
	return nil
}

func cleanCA2023Destination(value string) (string, error) {
	value = filepath.FromSlash(strings.TrimSpace(value))
	clean := filepath.Clean(value)
	if value == "" || clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid Windows CA 2023 destination %q", value)
	}
	return clean, nil
}

// Replaces reports whether base ISO verification must defer one exact path to
// the CA 2023-specific SHA-256 readback.
func (plan *WindowsCA2023Plan) Replaces(relative string) bool {
	if plan == nil {
		return false
	}
	_, ok := plan.replacements[strings.ToLower(filepath.ToSlash(filepath.Clean(relative)))]
	return ok
}

func verifyWindowsCA2023Staging(plan *WindowsCA2023Plan) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		if err := verifyStagedWindowsCA2023Asset(asset); err != nil {
			return err
		}
	}
	return nil
}

func verifyStagedWindowsCA2023Asset(asset WindowsCA2023Asset) error {
	info, err := os.Lstat(asset.sourcePath)
	if err != nil {
		return fmt.Errorf("restat staged CA 2023 asset %s: %w", asset.Destination, err)
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != asset.Size {
		return fmt.Errorf("staged CA 2023 asset %s changed type or size after pre-erasure validation", asset.Destination)
	}
	digest, err := fileSHA256(asset.sourcePath)
	if err != nil {
		return fmt.Errorf("rehash staged CA 2023 asset %s: %w", asset.Destination, err)
	}
	if hex.EncodeToString(digest[:]) != asset.SHA256 {
		return fmt.Errorf("staged CA 2023 asset %s changed after pre-erasure validation", asset.Destination)
	}
	return nil
}

func applyWindowsCA2023(ctx context.Context, root string, plan *WindowsCA2023Plan, progress func(uint64)) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyStagedWindowsCA2023Asset(asset); err != nil {
			return err
		}
		destination, err := prepareCA2023Destination(root, asset.Destination)
		if err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(destination), ".rufus-ca2023-")
		if err != nil {
			return fmt.Errorf("create temporary CA 2023 destination: %w", err)
		}
		temporaryPath := temporary.Name()
		cleanup := func() {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
		source, err := os.Open(asset.sourcePath)
		if err != nil {
			cleanup()
			return fmt.Errorf("open staged CA 2023 asset: %w", err)
		}
		written, copyErr := io.CopyBuffer(temporary, source, make([]byte, copyBufferSize))
		copyErr = errors.Join(copyErr, source.Close())
		if copyErr == nil {
			copyErr = temporary.Sync()
		}
		if copyErr == nil {
			copyErr = temporary.Chmod(0o644)
		}
		copyErr = errors.Join(copyErr, temporary.Close())
		if copyErr != nil {
			cleanup()
			return fmt.Errorf("publish CA 2023 asset %s: %w", asset.Destination, copyErr)
		}
		if uint64(written) != asset.Size {
			cleanup()
			return fmt.Errorf("short CA 2023 asset write %s: wrote %d of %d bytes", asset.Destination, written, asset.Size)
		}
		if err := os.Rename(temporaryPath, destination); err != nil {
			cleanup()
			return fmt.Errorf("replace CA 2023 destination %s: %w", asset.Destination, err)
		}
		if progress != nil {
			progress(asset.Size)
		}
	}
	return nil
}

func prepareCA2023Destination(root, relative string) (string, error) {
	clean, err := cleanCA2023Destination(relative)
	if err != nil {
		return "", err
	}
	current := root
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(current, 0o755); err != nil {
				return "", err
			}
		case statErr != nil:
			return "", statErr
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return "", fmt.Errorf("CA 2023 destination parent is not a real directory: %s", current)
		}
	}
	destination := filepath.Join(root, clean)
	if info, statErr := os.Lstat(destination); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("CA 2023 destination is not a regular file: %s", filepath.ToSlash(clean))
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	return destination, nil
}

func existingCA2023Destination(root, relative string) (string, error) {
	clean, err := cleanCA2023Destination(relative)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("CA 2023 readback root is not a real directory")
	}
	current := root
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", fmt.Errorf("stat CA 2023 readback parent %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("CA 2023 readback parent is not a real directory: %s", current)
		}
	}
	return filepath.Join(root, clean), nil
}

func verifyWindowsCA2023(root string, plan *WindowsCA2023Plan) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		destination, err := existingCA2023Destination(root, asset.Destination)
		if err != nil {
			return err
		}
		info, err := os.Lstat(destination)
		if err != nil {
			return fmt.Errorf("stat CA 2023 replacement %s: %w", asset.Destination, err)
		}
		if !info.Mode().IsRegular() || uint64(info.Size()) != asset.Size {
			return fmt.Errorf("CA 2023 replacement %s has unexpected type or size", asset.Destination)
		}
		digest, err := fileSHA256(destination)
		if err != nil {
			return fmt.Errorf("hash CA 2023 replacement %s: %w", asset.Destination, err)
		}
		if hex.EncodeToString(digest[:]) != asset.SHA256 {
			return fmt.Errorf("CA 2023 replacement %s failed SHA-256 readback", asset.Destination)
		}
	}
	return nil
}
