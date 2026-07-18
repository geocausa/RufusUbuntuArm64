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
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const persistentAnalysisSectorSize = uint64(512)

// PersistentAnalysisOptions describes a read-only persistence compatibility
// analysis. TargetSize is only geometry supplied by the caller; no target path
// is accepted or opened by this API.
type PersistentAnalysisOptions struct {
	ExpectedSource     sourcefile.Identity
	TargetSize         uint64
	PersistenceSize    uint64
	Architecture       string
	WorkDirectory      string
	ManifestMaxEntries int
	ManifestMaxBytes   uint64
}

// PersistentAnalysisResult describes the same fresh GPT/FAT32/ext4 layout used
// by CreatePersistent. Plan is retained for existing CLI and GUI consumers and
// is the persistence partition within Layout, not an extension of the ISO's
// embedded hybrid partition table.
type PersistentAnalysisResult struct {
	Detection          persistence.Detection `json:"detection"`
	Plan               persistence.Plan      `json:"plan"`
	Layout             PersistentLayout      `json:"layout"`
	ImageSize          uint64                `json:"image_size"`
	TargetSize         uint64                `json:"target_size"`
	ManifestEntries    int                   `json:"manifest_entries"`
	ManifestBytes      uint64                `json:"manifest_bytes"`
	FAT32RequiredBytes uint64                `json:"fat32_required_bytes"`
}

type persistentAnalysisRunner func(context.Context, string, ...string) error

// AnalyzePersistent mounts a plain raw-bootable ISOHybrid image read-only,
// validates the same writable-media requirements as CreatePersistent, and
// returns a fresh two-partition GPT plan. It never accepts a target path and
// cannot write a USB drive. Creation repeats the plan using the target's actual
// logical sector size before any destructive action.
func AnalyzePersistent(ctx context.Context, isoPath string, opts PersistentAnalysisOptions, emit PersistentEventFunc) (PersistentAnalysisResult, error) {
	for _, name := range []string{"mount", "umount"} {
		if _, err := exec.LookPath(name); err != nil {
			return PersistentAnalysisResult{}, fmt.Errorf("required program %q is not installed", name)
		}
	}
	return analyzePersistentWithRunner(ctx, isoPath, opts, emit, runPersistentQuiet)
}

func analyzePersistentWithRunner(ctx context.Context, isoPath string, opts PersistentAnalysisOptions, emit PersistentEventFunc, runner persistentAnalysisRunner) (result PersistentAnalysisResult, returnErr error) {
	if ctx == nil {
		return result, errors.New("persistence analysis context is nil")
	}
	if runner == nil {
		return result, errors.New("persistence analysis command runner is nil")
	}
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return result, errors.New("automatic persistence analysis requires an identity-bound source image")
	}
	if opts.TargetSize == 0 {
		return result, errors.New("automatic persistence analysis requires a non-zero target size")
	}

	image, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return result, err
	}
	defer image.Close()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), image.Fd())

	probe, err := imaging.ProbeInput(isoPath, image)
	if err != nil {
		return result, err
	}
	if probe.Kind != imaging.InputPlain {
		return result, errors.New("automatic persistence analysis requires a plain ISOHybrid image; compressed and virtual-disk inputs are not accepted")
	}
	inspection, err := imaging.InspectOpenFile(image)
	if err != nil {
		return result, err
	}
	if !inspection.HasOpticalFilesystem() || !inspection.LooksLikeRawBootMedia() {
		return result, errors.New("automatic persistence analysis requires a recognized raw-bootable ISOHybrid image")
	}

	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-persistence-analysis-")
	if err != nil {
		return result, fmt.Errorf("create persistence analysis workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("secure persistence analysis workspace: %w", err)
	}
	mountRoot := filepath.Join(workDir, "media")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("create persistence analysis mountpoint: %w", err)
	}

	mounted := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mounted {
			if err := runner(cleanupCtx, "umount", "--", mountRoot); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup persistence analysis mount: %w", err))
			} else {
				mounted = false
			}
		}
		if !mounted {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove persistence analysis workspace: %w", err))
			}
		}
	}()

	sendPersistent(emit, PersistentEvent{Stage: "mount", Message: "Mounting the selected Linux image read-only for compatibility analysis…"})
	if err := runner(ctx, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, mountRoot); err != nil {
		return result, fmt.Errorf("mount Linux image read-only: %w", err)
	}
	mounted = true
	if err := ctx.Err(); err != nil {
		return result, err
	}

	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Inspecting Ubuntu casper or Debian live-boot persistence compatibility…"})
	detection, err := persistence.Detect(os.DirFS(mountRoot))
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !detection.Ready() {
		return result, fmt.Errorf("detected %s but its persistence contract is outside the supported scope", detection.DisplayName)
	}

	architecture := strings.TrimSpace(opts.Architecture)
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Checking the complete media tree, fallback UEFI loader, FAT32 safety, and required boot capacity…"})
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
	layout, err := PlanPersistentLayout(opts.TargetSize, persistentAnalysisSectorSize, fat32Bytes, opts.PersistenceSize, detection)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := sourcefile.VerifyPinned(image, opts.ExpectedSource); err != nil {
		return result, err
	}

	result = PersistentAnalysisResult{
		Detection:          detection,
		Plan:               layout.Plan,
		Layout:             layout,
		ImageSize:          uint64(opts.ExpectedSource.Size),
		TargetSize:         opts.TargetSize,
		ManifestEntries:    len(manifest.Entries),
		ManifestBytes:      manifest.TotalBytes,
		FAT32RequiredBytes: fat32Bytes,
	}
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: "Fresh GPT/FAT32/ext4 persistence analysis completed without modifying the image or USB drive."})
	return result, nil
}
