//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

// PersistentAnalysisOptions describes a read-only persistence compatibility
// analysis. TargetSize is only geometry supplied by the caller; no target path
// is accepted or opened by this API.
type PersistentAnalysisOptions struct {
	ExpectedSource  sourcefile.Identity
	TargetSize      uint64
	PersistenceSize uint64
	WorkDirectory   string
}

// PersistentAnalysisResult is the same bounded detector and append-only plan
// produced by the manual persistence planner, but with the ISO mounted in a
// private read-only workspace by the helper.
type PersistentAnalysisResult struct {
	Detection  persistence.Detection `json:"detection"`
	Plan       persistence.Plan      `json:"plan"`
	ImageSize  uint64                `json:"image_size"`
	TargetSize uint64                `json:"target_size"`
}

type persistentAnalysisRunner func(context.Context, string, ...string) error

// AnalyzePersistent mounts a plain raw-bootable ISOHybrid image read-only,
// detects the supported persistence contract, and returns a non-destructive
// partition plan. It never accepts a target path and cannot write a USB drive.
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
	plan, err := persistence.BuildPlan(image, uint64(opts.ExpectedSource.Size), opts.TargetSize, opts.PersistenceSize, detection)
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
		Detection:  detection,
		Plan:       plan,
		ImageSize:  uint64(opts.ExpectedSource.Size),
		TargetSize: opts.TargetSize,
	}
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: "Persistence compatibility analysis completed without modifying the image or USB drive."})
	return result, nil
}
