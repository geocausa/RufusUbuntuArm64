//go:build linux

package linuxmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

// ExtractedDispatchOptions adds the Rufus-style filesystem selector while
// preserving the existing identity-bound creation options.
type ExtractedDispatchOptions struct {
	ExtractedCreateOptions
	Filesystem string
}

// ExtractedDispatchResult contains exactly one selected creation result.
type ExtractedDispatchResult struct {
	Selection ExtractedFilesystemSelection `json:"selection"`
	FAT32     *ExtractedCreateResult       `json:"fat32,omitempty"`
	NTFS      *ExtractedNTFSCreateResult   `json:"ntfs,omitempty"`
}

// CreateExtractedSelected dispatches the existing FAT32 path or the separate
// NTFS/UEFI:NTFS path. Automatic selection is derived from a read-only complete
// tree inspection and is then independently revalidated by the selected writer.
func CreateExtractedSelected(ctx context.Context, isoPath, devicePath string, opts ExtractedDispatchOptions, emit PersistentEventFunc) (ExtractedDispatchResult, error) {
	requested, err := normalizeExtractedFilesystem(opts.Filesystem)
	if err != nil {
		return ExtractedDispatchResult{}, err
	}
	selection := ExtractedFilesystemSelection{Requested: requested, Selected: requested}
	if requested == ExtractedFilesystemAutomatic {
		selection, err = SelectExtractedFilesystemImage(ctx, isoPath, opts.ExtractedCreateOptions, emit)
		if err != nil {
			return ExtractedDispatchResult{}, err
		}
		sendPersistent(emit, PersistentEvent{
			Stage:   "inspect",
			Message: automaticExtractedFilesystemMessage(selection),
		})
	}

	switch selection.Selected {
	case ExtractedFilesystemFAT32:
		result, err := CreateExtracted(ctx, isoPath, devicePath, opts.ExtractedCreateOptions, emit)
		if err != nil {
			return ExtractedDispatchResult{}, err
		}
		return ExtractedDispatchResult{Selection: selection, FAT32: &result}, nil
	case ExtractedFilesystemNTFS:
		result, err := CreateExtractedNTFS(ctx, isoPath, devicePath, opts.ExtractedCreateOptions, emit)
		if err != nil {
			return ExtractedDispatchResult{}, err
		}
		return ExtractedDispatchResult{Selection: selection, NTFS: &result}, nil
	default:
		return ExtractedDispatchResult{}, fmt.Errorf("unsupported selected Linux ISO Image mode filesystem %q", selection.Selected)
	}
}

// SelectExtractedFilesystemImage performs only the read-only Automatic
// selection pass. It never opens or mutates the target device.
func SelectExtractedFilesystemImage(ctx context.Context, isoPath string, opts ExtractedCreateOptions, emit PersistentEventFunc) (selection ExtractedFilesystemSelection, returnErr error) {
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return selection, errors.New("automatic ISO Image mode selection requires an identity-bound source image")
	}
	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return selection, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, isoFile.Close())
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

	sourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
	switch {
	case leaseErr == nil:
		ctx = sourceLease.Context()
		defer func() {
			returnErr = errors.Join(returnErr, sourceLease.Check(), sourceLease.Close())
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		sourceLease = nil
	default:
		return selection, fmt.Errorf("hold selected Linux image for automatic filesystem inspection: %w", leaseErr)
	}

	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = os.TempDir()
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-linux-iso-select-")
	if err != nil {
		return selection, fmt.Errorf("create automatic filesystem inspection workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return selection, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, os.RemoveAll(workDir))
	}()
	isoMount := filepath.Join(workDir, "iso")
	if err := os.Mkdir(isoMount, 0o700); err != nil {
		return selection, err
	}
	mounted := false
	defer func() {
		if mounted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", isoMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup automatic filesystem inspection mount: %w", err))
			}
		}
	}()

	sourceRoot := ""
	if testRoot := strings.TrimSpace(os.Getenv("RUFUS_TEST_ISO_ROOT")); testRoot != "" {
		sourceRoot, err = resolveRoot(testRoot)
		if err != nil {
			return selection, err
		}
	} else {
		sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Inspecting the selected Linux image to choose FAT32 or NTFS…"})
		if err := runPersistent(ctx, emit, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, isoMount); err != nil {
			return selection, fmt.Errorf("mount Linux image for automatic filesystem inspection: %w", err)
		}
		mounted = true
		sourceRoot = isoMount
	}

	manifest, err := Inspect(ctx, sourceRoot, Options{
		Architecture: opts.Architecture,
		RequireUEFI:  true,
		RequireFAT32: false,
		MaxEntries:   opts.ManifestMaxEntries,
		MaxBytes:     opts.ManifestMaxBytes,
	})
	if err != nil {
		return selection, fmt.Errorf("inspect Linux image for automatic filesystem selection: %w", err)
	}
	if err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
		return selection, err
	}
	return ResolveExtractedFilesystem("auto", manifest)
}

func automaticExtractedFilesystemMessage(selection ExtractedFilesystemSelection) string {
	if selection.Selected == ExtractedFilesystemNTFS && selection.FAT32Refusal != "" {
		return fmt.Sprintf("Automatic filesystem selection chose NTFS because FAT32 is incompatible: %s", selection.FAT32Refusal)
	}
	return "Automatic filesystem selection chose FAT32 because the complete inspected media tree is compatible."
}
