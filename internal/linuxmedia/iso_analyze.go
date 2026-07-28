//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

// ISOImageAnalysisOptions contains only source identity and target geometry.
// No target path is accepted, so analysis cannot modify a USB drive.
type ISOImageAnalysisOptions struct {
	ExpectedSource     sourcefile.Identity
	TargetSize         uint64
	Architecture       string
	WorkDirectory      string
	ManifestMaxEntries int
	ManifestMaxBytes   uint64
}

// ISOImageAnalysisResult is the complete read-only decision used by the GUI to
// offer ISO Image mode. A successful result means the current image tree fits
// the selected target and is representable by the bounded GPT/UEFI/FAT32 path.
type ISOImageAnalysisResult struct {
	Layout              ISOImageLayout `json:"layout"`
	ImageSize           uint64         `json:"image_size"`
	TargetSize          uint64         `json:"target_size"`
	ManifestEntries     int            `json:"manifest_entries"`
	ManifestFiles       int            `json:"manifest_files"`
	ManifestDirectories int            `json:"manifest_directories"`
	ManifestBytes       uint64         `json:"manifest_bytes"`
	FAT32RequiredBytes  uint64         `json:"fat32_required_bytes"`
	UEFIBootPath        string         `json:"uefi_boot_path"`
	Architecture        string         `json:"architecture"`
}

// AnalyzeISOImage mounts a plain Linux ISOHybrid image privately and read-only,
// hashes the complete tree, validates the fallback UEFI loader and FAT32 path
// rules, and plans a fresh single-partition target. It never opens a target.
func AnalyzeISOImage(ctx context.Context, isoPath string, opts ISOImageAnalysisOptions, emit PersistentEventFunc) (result ISOImageAnalysisResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("ISO Image mode analysis context is nil")
	}
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return result, errors.New("ISO Image mode analysis requires an identity-bound source image")
	}
	if opts.TargetSize == 0 {
		return result, errors.New("ISO Image mode analysis requires a non-zero target size")
	}
	for _, name := range []string{"mount", "umount"} {
		if _, err := exec.LookPath(name); err != nil {
			return result, fmt.Errorf("required program %q is not installed", name)
		}
	}

	image, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return result, err
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, image, false, "selected Linux ISO")
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), image.Fd())

	probe, err := imaging.ProbeInput(isoPath, image)
	if err != nil {
		return result, err
	}
	if probe.Kind != imaging.InputPlain {
		return result, errors.New("ISO Image mode requires a plain ISOHybrid image; compressed and virtual-disk inputs remain available through DD mode")
	}
	inspection, err := imaging.InspectOpenFile(image)
	if err != nil {
		return result, err
	}
	if !inspection.HasOpticalFilesystem() || !inspection.LooksLikeRawBootMedia() {
		return result, errors.New("ISO Image mode requires a recognized raw-bootable ISOHybrid image")
	}

	workRoot := strings.TrimSpace(opts.WorkDirectory)
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-iso-image-analysis-")
	if err != nil {
		return result, fmt.Errorf("create ISO Image mode analysis workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("secure ISO Image mode analysis workspace: %w", err)
	}
	mountRoot := filepath.Join(workDir, "media")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("create ISO Image mode mountpoint: %w", err)
	}
	mounted := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mounted {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", mountRoot); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup ISO Image mode analysis mount: %w", err))
			} else {
				mounted = false
			}
		}
		if !mounted {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove ISO Image mode analysis workspace: %w", err))
			}
		}
	}()

	sendPersistent(emit, PersistentEvent{Stage: "mount", Message: "Mounting the selected Linux ISO read-only for ISO Image mode analysis…"})
	if err := runPersistentQuiet(ctx, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, mountRoot); err != nil {
		return result, fmt.Errorf("mount Linux ISO read-only: %w", err)
	}
	mounted = true
	if err := ctx.Err(); err != nil {
		return result, err
	}

	architecture := strings.ToLower(strings.TrimSpace(opts.Architecture))
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Hashing the complete ISO tree and checking UEFI/FAT32 compatibility…"})
	manifest, err := Inspect(ctx, mountRoot, Options{
		Architecture: architecture,
		RequireUEFI:  true,
		RequireFAT32: true,
		MaxEntries:   opts.ManifestMaxEntries,
		MaxBytes:     opts.ManifestMaxBytes,
	})
	if err != nil {
		return result, err
	}
	fat32Bytes, err := EstimateFAT32Bytes(manifest)
	if err != nil {
		return result, err
	}
	layout, err := PlanISOImageLayout(opts.TargetSize, persistentAnalysisSectorSize, fat32Bytes)
	if err != nil {
		return result, err
	}
	if err := sourcefile.VerifyPinned(image, opts.ExpectedSource); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	result = ISOImageAnalysisResult{
		Layout:              layout,
		ImageSize:           uint64(opts.ExpectedSource.Size),
		TargetSize:          opts.TargetSize,
		ManifestEntries:     len(manifest.Entries),
		ManifestFiles:       manifest.Files,
		ManifestDirectories: manifest.Directories,
		ManifestBytes:       manifest.TotalBytes,
		FAT32RequiredBytes:  fat32Bytes,
		UEFIBootPath:        manifest.UEFIBootPath,
		Architecture:        architecture,
	}
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: "ISO Image mode is available for this image and target; no data was modified."})
	return result, nil
}
