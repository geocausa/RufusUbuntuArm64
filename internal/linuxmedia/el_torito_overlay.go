//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/imaging"
)

type preparedExtractedManifest struct {
	Manifest      Manifest
	overlayMount  string
	overlayImage  string
	overlaySource *os.File
	mounted       bool
}

func (prepared *preparedExtractedManifest) Close() error {
	if prepared == nil {
		return nil
	}
	var result error
	if prepared.mounted {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := runPersistentQuiet(ctx, "umount", "--", prepared.overlayMount); err != nil {
			result = errors.Join(result, fmt.Errorf("unmount El Torito overlay: %w", err))
		} else {
			prepared.mounted = false
		}
		cancel()
	}
	if prepared.overlaySource != nil {
		result = errors.Join(result, prepared.overlaySource.Close())
		prepared.overlaySource = nil
	}
	if !prepared.mounted {
		if prepared.overlayImage != "" {
			result = errors.Join(result, removeIfPresent(prepared.overlayImage))
		}
		if prepared.overlayMount != "" {
			result = errors.Join(result, os.Remove(prepared.overlayMount))
		}
	}
	return result
}

func prepareExtractedManifest(ctx context.Context, isoFile *os.File, sourceRoot, workDir string, opts Options, allowTestOverlay bool, emit PersistentEventFunc) (*preparedExtractedManifest, error) {
	if ctx == nil {
		return nil, errors.New("el Torito overlay context is nil")
	}
	if isoFile == nil {
		return nil, errors.New("el Torito overlay requires the held ISO descriptor")
	}
	normalized, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	if !normalized.RequireUEFI {
		return nil, errors.New("el Torito overlay preparation requires a UEFI fallback contract")
	}
	baseOptions := normalized
	baseOptions.RequireUEFI = false
	base, err := Inspect(ctx, sourceRoot, baseOptions)
	if err != nil {
		return nil, err
	}
	prepared := &preparedExtractedManifest{Manifest: base}
	if base.UEFIBootPath != "" {
		return prepared, nil
	}

	testRoot := ""
	if allowTestOverlay {
		testRoot = strings.TrimSpace(os.Getenv("RUFUS_TEST_EL_TORITO_ROOT"))
	}
	if testRoot != "" {
		overlayRoot, err := resolveRoot(testRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve test El Torito overlay root: %w", err)
		}
		overlay, err := Inspect(ctx, overlayRoot, normalized)
		if err != nil {
			return nil, fmt.Errorf("inspect test El Torito overlay: %w", err)
		}
		merged, err := MergeManifestOverlay(base, overlay, normalized)
		if err != nil {
			return nil, err
		}
		prepared.Manifest = merged
		return prepared, nil
	}

	info, err := isoFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat held ISO for El Torito extraction: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return nil, errors.New("held El Torito source is not a non-empty regular ISO")
	}
	if strings.TrimSpace(workDir) == "" {
		return nil, errors.New("el Torito overlay requires a private workspace")
	}
	overlayMount := filepath.Join(workDir, "el-torito")
	if err := os.Mkdir(overlayMount, 0o700); err != nil {
		return nil, fmt.Errorf("create El Torito overlay mount: %w", err)
	}
	prepared.overlayMount = overlayMount
	overlayFile, err := os.OpenFile(filepath.Join(workDir, "el-torito-uefi.img"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = os.Remove(overlayMount)
		return nil, fmt.Errorf("create El Torito overlay image: %w", err)
	}
	prepared.overlayImage = overlayFile.Name()
	cleanupFailure := func(cause error) (*preparedExtractedManifest, error) {
		closeErr := overlayFile.Close()
		return nil, errors.Join(cause, closeErr, prepared.Close())
	}
	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Extracting the single validated El Torito UEFI boot image before erasure…"})
	plan, err := imaging.ExtractElToritoUEFIImage(ctx, isoFile, info.Size(), overlayFile)
	if err != nil {
		return cleanupFailure(fmt.Errorf("extract El Torito UEFI image: %w", err))
	}
	if err := overlayFile.Sync(); err != nil {
		return cleanupFailure(fmt.Errorf("sync El Torito overlay image: %w", err))
	}
	if err := overlayFile.Close(); err != nil {
		return nil, errors.Join(fmt.Errorf("close El Torito overlay image: %w", err), prepared.Close())
	}
	overlayFile = nil
	prepared.overlaySource, err = os.OpenFile(prepared.overlayImage, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("reopen El Torito overlay image: %w", err), prepared.Close())
	}
	imageInfo, err := prepared.overlaySource.Stat()
	if err != nil || !imageInfo.Mode().IsRegular() || imageInfo.Size() < 0 || uint64(imageInfo.Size()) != plan.ImageLength {
		return nil, errors.Join(errors.New("extracted El Torito overlay image size or type does not match its plan"), prepared.Close())
	}
	if err := runPersistentFile(ctx, emit, prepared.overlaySource, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", "/proc/self/fd/3", prepared.overlayMount); err != nil {
		return nil, errors.Join(fmt.Errorf("mount El Torito UEFI image: %w", err), prepared.Close())
	}
	prepared.mounted = true
	if err := verifyReadOnlyLoopFilesystemMount(ctx, prepared.overlayMount, "vfat"); err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	overlay, err := Inspect(ctx, prepared.overlayMount, normalized)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect El Torito UEFI overlay: %w", err), prepared.Close())
	}
	merged, err := MergeManifestOverlay(base, overlay, normalized)
	if err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	merged.ElToritoOverlay = &ElToritoOverlayEvidence{
		PlanSHA256: plan.PlanSHA256, CatalogSHA256: plan.CatalogSHA256, ImageSHA256: plan.ImageSHA256,
		ImageOffset: plan.ImageOffset, ImageLength: plan.ImageLength,
	}
	prepared.Manifest = merged
	sendPersistent(emit, PersistentEvent{
		Stage:   "inspect",
		Message: fmt.Sprintf("Using verified El Torito UEFI overlay %s (%d bytes) for fallback path %s.", plan.ImageSHA256, plan.ImageLength, merged.UEFIBootPath),
	})
	return prepared, nil
}

func verifyReadOnlyLoopFilesystemMount(ctx context.Context, target, expectedFilesystem string) error {
	command := exec.CommandContext(ctx, "findmnt", "-rn", "-T", target, "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("inspect private El Torito mount: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 4 || filepath.Clean(fields[0]) != filepath.Clean(target) || !strings.HasPrefix(fields[1], "/dev/loop") || fields[2] != expectedFilesystem {
		return fmt.Errorf("private El Torito mount has unexpected target, source, or filesystem: %q", strings.TrimSpace(string(output)))
	}
	options := strings.Split(fields[3], ",")
	required := map[string]bool{"ro": false, "nosuid": false, "nodev": false, "noexec": false}
	for _, option := range options {
		if option == "rw" {
			return errors.New("private El Torito mount is writable")
		}
		if _, exists := required[option]; exists {
			required[option] = true
		}
	}
	for option, present := range required {
		if !present {
			return fmt.Errorf("private El Torito mount is missing %s", option)
		}
	}
	return nil
}

func removeIfPresent(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
