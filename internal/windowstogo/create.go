//go:build linux

package windowstogo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/trustedexec"
	"github.com/geocausa/RufusArm64/internal/windowsmedia"
)

// CreateOptions binds one reviewed source and target to an experimental
// Windows To Go transaction. The caller remains responsible for whole-disk
// selection policy; Create independently verifies the already-open block
// device identity, capacity, sector size, source identity, and mount state.
type CreateOptions struct {
	TargetSizeBytes   uint64
	LogicalSectorSize uint64
	ExpectedDeviceID  uint64
	ExpectedIdentity  string
	ExpectedSource    sourcefile.Identity
	ImageIndex        int
	Customizations    Customizations
	BeforeDestructive func(source *os.File) error
}

type Event struct {
	Stage   string  `json:"stage"`
	Message string  `json:"message"`
	Done    uint64  `json:"done,omitempty"`
	Total   uint64  `json:"total,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
	Hash    string  `json:"sha256,omitempty"`
}

type EventFunc func(Event)

type Result struct {
	Plan                    Plan                    `json:"plan"`
	GPT                     GPTLayout               `json:"gpt"`
	Materialization         MaterializationEvidence `json:"materialization"`
	SourceSHA256            string                  `json:"source_sha256"`
	PreflightBootManagerSHA string                  `json:"preflight_boot_manager_authenticode_sha256"`
	FirmwareBootVerified    bool                    `json:"firmware_boot_verified"`
}

// Create erases devicePath and constructs the narrow GPT/UEFI/ARM64/NTFS
// Windows To Go profile admitted by BuildPlan. Software verification deliberately
// leaves FirmwareBootVerified false; only a real firmware boot can change that
// claim in separate qualification evidence.
func Create(ctx context.Context, isoPath, devicePath string, options CreateOptions, emit EventFunc) (result Result, returnErr error) {
	if ctx == nil {
		return Result{}, errors.New("windows To Go context is nil")
	}
	if err := safety.RequireRoot(); err != nil {
		return Result{}, err
	}
	if options.TargetSizeBytes == 0 || options.ExpectedDeviceID == 0 || options.ExpectedIdentity == "" ||
		(options.LogicalSectorSize != 512 && options.LogicalSectorSize != 4096) || options.ImageIndex <= 0 {
		return Result{}, errors.New("windows To Go requires exact target size, kernel identity, canonical selection identity, sector size, and image index")
	}

	isoFile, err := sourcefile.OpenRegular(isoPath, options.ExpectedSource)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if err := isoFile.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close selected Windows ISO: %w", err))
		}
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
	targetChanged := false

	lease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, options.ExpectedSource)
	switch {
	case leaseErr == nil:
		ctx = lease.Context()
		sendEvent(emit, Event{Stage: "source_hold", Message: "Holding the selected Windows ISO read-only with a Linux kernel lease."})
		defer func() {
			heldErr := lease.Check()
			if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
				message := "the selected Windows ISO was opened for writing before the target was erased"
				if targetChanged {
					message = "the selected Windows ISO was opened for writing during Windows To Go creation; the target is incomplete"
				}
				heldErr = fmt.Errorf("%s: %w", message, heldErr)
			}
			returnErr = errors.Join(returnErr, heldErr, lease.Close())
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		lease = nil
		sendEvent(emit, Event{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 verification.", leaseErr)})
	default:
		return Result{}, fmt.Errorf("hold selected Windows ISO stable: %w", leaseErr)
	}

	hashSource := func(stage, message string) ([sha256.Size]byte, error) {
		var last time.Time
		digest, err := sourcefile.SHA256Open(ctx, isoFile, func(done, total uint64) {
			now := time.Now()
			if done == total || now.Sub(last) >= 250*time.Millisecond {
				last = now
				sendEvent(emit, Event{Stage: stage, Message: message, Done: done, Total: total})
			}
		})
		if err != nil {
			return digest, err
		}
		if err := sourcefile.VerifyPinned(isoFile, options.ExpectedSource); err != nil {
			return digest, err
		}
		return digest, nil
	}
	initialDigest, err := hashSource("hash_source", "Hashing the exact selected Windows ISO before preparation…")
	if err != nil {
		return Result{}, fmt.Errorf("hash selected Windows ISO: %w", err)
	}
	result.SourceSHA256 = hex.EncodeToString(initialDigest[:])

	target, err := safety.OpenReopenableDevice(devicePath)
	if err != nil {
		return Result{}, fmt.Errorf("open Windows To Go target: %w", err)
	}
	locked := false
	defer func() {
		if locked {
			if err := syscall.Flock(int(target.Fd()), syscall.LOCK_UN); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("unlock Windows To Go target: %w", err))
			}
		}
		if err := target.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close Windows To Go target: %w", err))
		}
	}()
	if err := safety.VerifyOpenDevice(target, options.ExpectedDeviceID, options.TargetSizeBytes); err != nil {
		return Result{}, err
	}
	if err := safety.AcquireExclusiveFlock(ctx, target); err != nil {
		return Result{}, fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	locked = true

	mountTool, err := resolveEarlyTool("mount")
	if err != nil {
		return Result{}, err
	}
	umountTool, err := resolveEarlyTool("umount")
	if err != nil {
		return Result{}, err
	}
	findmntTool, err := resolveEarlyTool("findmnt")
	if err != nil {
		return Result{}, err
	}
	workDir, err := createSecureWorkDir()
	if err != nil {
		return Result{}, err
	}
	if err := safety.EnsurePathNotOnTarget(workDir, devicePath); err != nil {
		_ = os.RemoveAll(workDir)
		return Result{}, fmt.Errorf("temporary Windows To Go workspace is unsafe: %w", err)
	}
	isoMount := filepath.Join(workDir, "iso")
	osMount := filepath.Join(workDir, "windows")
	espMount := filepath.Join(workDir, "esp")
	for _, path := range []string{isoMount, osMount, espMount} {
		if err := os.Mkdir(path, 0o700); err != nil {
			_ = os.RemoveAll(workDir)
			return Result{}, err
		}
	}
	mountedISO, mountedOS, mountedESP := false, false, false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for _, item := range []struct {
			mounted *bool
			path    string
			label   string
		}{{&mountedESP, espMount, "ESP"}, {&mountedOS, osMount, "Windows"}, {&mountedISO, isoMount, "ISO"}} {
			if *item.mounted {
				if err := runTool(cleanupCtx, umountTool, "--", item.path); err != nil {
					returnErr = errors.Join(returnErr, fmt.Errorf("cleanup %s mount: %w", item.label, err))
				} else {
					*item.mounted = false
				}
			}
		}
		if !mountedISO && !mountedOS && !mountedESP {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove Windows To Go workspace: %w", err))
			}
		}
	}()

	sendEvent(emit, Event{Stage: "inspect", Message: "Mounting the selected Windows ISO privately and read-only…"})
	if err := runTool(ctx, mountTool, "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, isoMount); err != nil {
		return Result{}, fmt.Errorf("mount Windows ISO: %w", err)
	}
	mountedISO = true
	if err := verifyReadOnlyLoopMount(ctx, findmntTool, isoMount); err != nil {
		return Result{}, err
	}
	payload, err := windowsmedia.InspectMountedInstallPayload(isoMount)
	if err != nil {
		return Result{}, err
	}
	if !payload.HasARM64 {
		return Result{}, errors.New("experimental Windows To Go requires an ARM64 UEFI installation payload")
	}
	wimExecutable, err := resolveWIMExecutable()
	if err != nil {
		return Result{}, err
	}
	metadata, err := windowsmedia.InspectWIMMetadataWithExecutable(ctx, wimExecutable, payload.PrimaryPath)
	if err != nil {
		return Result{}, fmt.Errorf("inspect Windows To Go image metadata: %w", err)
	}
	plan, err := BuildPlan(Request{
		TargetPath: devicePath, ExpectedIdentity: options.ExpectedIdentity,
		TargetSizeBytes: options.TargetSizeBytes, LogicalSectorSize: options.LogicalSectorSize,
		Metadata: metadata, ImageIndex: options.ImageIndex, Customizations: options.Customizations,
	})
	if err != nil {
		return Result{}, err
	}
	result.Plan = plan
	tools, err := resolveRequiredTools(plan)
	if err != nil {
		return Result{}, err
	}
	if tools["mount"] != mountTool || tools["umount"] != umountTool || tools["findmnt"] != findmntTool || tools["wimlib-imagex"] != wimExecutable {
		return Result{}, errors.New("windows To Go tool resolution changed during preflight")
	}
	liveSector, err := liveLogicalSectorSize(ctx, tools["blockdev"], devicePath)
	if err != nil {
		return Result{}, err
	}
	if liveSector != options.LogicalSectorSize {
		return Result{}, fmt.Errorf("target logical sector size changed from %d to %d bytes", options.LogicalSectorSize, liveSector)
	}

	sendEvent(emit, Event{Stage: "preflight", Message: "Validating the selected image's ARM64 boot manager and BCD template before erasure…"})
	preflight, err := preflightImage(ctx, tools, payload, plan, workDir)
	if err != nil {
		return Result{}, err
	}
	result.PreflightBootManagerSHA = preflight.BootManagerAuthenticodeSHA256
	if lease != nil {
		if err := lease.Check(); err != nil {
			return Result{}, err
		}
	} else {
		preEraseDigest, err := hashSource("verify_source", "Rehashing the selected Windows ISO immediately before erasure…")
		if err != nil {
			return Result{}, err
		}
		if !bytes.Equal(initialDigest[:], preEraseDigest[:]) {
			return Result{}, errors.New("the selected Windows ISO changed during preflight; nothing was erased")
		}
	}
	metadataNow, err := windowsmedia.InspectWIMMetadataWithExecutable(ctx, wimExecutable, payload.PrimaryPath)
	if err != nil {
		return Result{}, fmt.Errorf("reinspect Windows image immediately before erasure: %w", err)
	}
	if !reflect.DeepEqual(metadata, metadataNow) {
		return Result{}, errors.New("windows image metadata changed during preflight; nothing was erased")
	}
	if err := safety.VerifyOpenDevice(target, options.ExpectedDeviceID, options.TargetSizeBytes); err != nil {
		return Result{}, err
	}
	if err := safety.EnsureNoMountedDescendants(devicePath); err != nil {
		return Result{}, err
	}
	if options.BeforeDestructive != nil {
		if err := options.BeforeDestructive(isoFile); err != nil {
			return Result{}, fmt.Errorf("final target safety check: %w", err)
		}
	}
	if err := safety.VerifyOpenDevice(target, options.ExpectedDeviceID, options.TargetSizeBytes); err != nil {
		return Result{}, err
	}
	if err := safety.EnsureNoMountedDescendants(devicePath); err != nil {
		return Result{}, err
	}

	targetChanged = true
	sendEvent(emit, Event{Stage: "partition", Message: "Erasing stale signatures and creating the reviewed GPT/UEFI layout…"})
	if err := runTool(ctx, tools["wipefs"], "--all", "--force", "--", devicePath); err != nil {
		return Result{}, err
	}
	if err := safety.VerifyOpenDevice(target, options.ExpectedDeviceID, options.TargetSizeBytes); err != nil {
		return Result{}, err
	}
	layout, err := BuildGPT(plan, rand.Reader)
	if err != nil {
		return Result{}, err
	}
	if err := WriteGPT(target, layout, plan); err != nil {
		return Result{}, err
	}
	result.GPT = layout
	if err := rereadPartitionTable(ctx, tools, devicePath); err != nil {
		return Result{}, err
	}
	espPath, err := waitForPartition(ctx, tools, devicePath, plan.ESP)
	if err != nil {
		return Result{}, err
	}
	osPath, err := waitForPartition(ctx, tools, devicePath, plan.OS)
	if err != nil {
		return Result{}, err
	}
	for _, path := range []string{espPath, osPath} {
		if err := unmountAll(ctx, tools, path); err != nil {
			return Result{}, err
		}
		if err := requireUnmounted(ctx, tools, path); err != nil {
			return Result{}, err
		}
	}

	sendEvent(emit, Event{Stage: "format", Message: "Formatting the unlabelled FAT32 ESP and Windows NTFS partition…"})
	if err := formatPartitions(ctx, tools, plan, espPath, osPath); err != nil {
		return Result{}, err
	}
	if err := requireUnmounted(ctx, tools, osPath); err != nil {
		return Result{}, err
	}

	applyMessage := fmt.Sprintf("Applying Windows image %d (%s) directly to the unmounted NTFS volume…", plan.Image.Index, plan.Image.Name)
	sendEvent(emit, Event{Stage: "apply", Message: applyMessage, Total: plan.Image.TotalBytes})
	// Direct NTFS-volume mode preserves Windows ACLs, reparse points, hard links,
	// object IDs, streams, and timestamps by default. Do not add --strict-acls:
	// the pinned engine's qualified real-volume path intentionally uses upstream
	// defaults, while --check is inapplicable to official images without an
	// optional WIM integrity table.
	applyArgs := []string{"apply", payload.PrimaryPath, strconv.Itoa(plan.Image.Index), osPath}
	for _, reference := range payload.ReferencePaths {
		applyArgs = append(applyArgs, "--ref="+reference)
	}
	health, err := newTargetHealthMonitor(devicePath, options.ExpectedDeviceID)
	if err != nil {
		return Result{}, fmt.Errorf("initialize Windows To Go target health monitor: %w", err)
	}
	if err := runWIMApply(ctx, wimExecutable, applyArgs, applyMessage, plan.Image.TotalBytes, health, applyHealthPollInterval, applyBlockedEscalationDelay, emit); err != nil {
		return Result{}, fmt.Errorf("apply selected Windows image: %w", err)
	}
	if err := runTool(ctx, tools["blockdev"], "--flushbufs", osPath); err != nil {
		return Result{}, fmt.Errorf("flush applied Windows volume: %w", err)
	}
	if err := runTool(ctx, tools["ntfsfix"], "-n", osPath); err != nil {
		return Result{}, fmt.Errorf("check applied Windows NTFS volume: %w", err)
	}

	if err := mountPrivate(ctx, tools, osPath, osMount, false); err != nil {
		return Result{}, fmt.Errorf("mount applied Windows volume privately: %w", err)
	}
	mountedOS = true
	if err := mountPrivate(ctx, tools, espPath, espMount, false); err != nil {
		return Result{}, fmt.Errorf("mount Windows To Go ESP privately: %w", err)
	}
	mountedESP = true
	sendEvent(emit, Event{Stage: "boot", Message: "Installing and verifying Microsoft ARM64 EFI boot files, BCD, and the Windows To Go first-boot answer file…"})
	materialization, err := Materialize(ctx, osMount, espMount, plan, layout)
	if err != nil {
		return Result{}, err
	}
	if materialization.BootManagerAuthenticodeSHA256 != preflight.BootManagerAuthenticodeSHA256 {
		return Result{}, errors.New("applied Windows boot manager differs from the pre-erasure image prerequisite")
	}
	result.Materialization = materialization
	for _, mountPath := range []string{osMount, espMount} {
		if err := syncFilesystem(mountPath); err != nil {
			return Result{}, fmt.Errorf("flush Windows To Go mount %s: %w", mountPath, err)
		}
	}
	if err := runTool(ctx, tools["umount"], "--", espMount); err != nil {
		return Result{}, err
	}
	mountedESP = false
	if err := runTool(ctx, tools["umount"], "--", osMount); err != nil {
		return Result{}, err
	}
	mountedOS = false
	for _, path := range []string{espPath, osPath} {
		if err := runTool(ctx, tools["blockdev"], "--flushbufs", path); err != nil {
			return Result{}, err
		}
	}
	if lease != nil {
		if err := lease.Check(); err != nil {
			return Result{}, err
		}
	} else {
		postApplyDigest, err := hashSource("verify_source", "Rehashing the selected Windows ISO after image application…")
		if err != nil {
			return Result{}, err
		}
		if !bytes.Equal(initialDigest[:], postApplyDigest[:]) {
			return Result{}, errors.New("the selected Windows ISO changed during image application; the target is incomplete")
		}
	}

	sendEvent(emit, Event{Stage: "verify", Message: "Reopening both filesystems read-only and independently verifying the completed media…"})
	if err := mountPrivate(ctx, tools, osPath, osMount, true); err != nil {
		return Result{}, err
	}
	mountedOS = true
	if err := mountPrivate(ctx, tools, espPath, espMount, true); err != nil {
		return Result{}, err
	}
	mountedESP = true
	if err := VerifyMaterialization(ctx, osMount, espMount, plan, layout, materialization); err != nil {
		return Result{}, err
	}
	if err := runTool(ctx, tools["umount"], "--", espMount); err != nil {
		return Result{}, err
	}
	mountedESP = false
	if err := runTool(ctx, tools["umount"], "--", osMount); err != nil {
		return Result{}, err
	}
	mountedOS = false
	if err := runTool(ctx, tools["fsck.vfat"], "-n", espPath); err != nil {
		return Result{}, fmt.Errorf("final FAT32 ESP check: %w", err)
	}
	if err := runTool(ctx, tools["ntfsfix"], "-n", osPath); err != nil {
		return Result{}, fmt.Errorf("final Windows NTFS check: %w", err)
	}
	if err := verifyFilesystemProbe(ctx, tools, espPath, "vfat", ""); err != nil {
		return Result{}, err
	}
	if err := verifyFilesystemProbe(ctx, tools, osPath, "ntfs", plan.OS.Label); err != nil {
		return Result{}, err
	}
	if err := VerifyGPTOnDevice(target, layout, plan); err != nil {
		return Result{}, err
	}
	if err := safety.VerifyOpenDevice(target, options.ExpectedDeviceID, options.TargetSizeBytes); err != nil {
		return Result{}, err
	}
	if err := sourcefile.VerifyPinned(isoFile, options.ExpectedSource); err != nil {
		return Result{}, err
	}
	result.FirmwareBootVerified = false
	sendEvent(emit, Event{Stage: "complete", Message: "Experimental Windows To Go media was created and independently verified; firmware boot remains untested.", Hash: result.SourceSHA256})
	return result, nil
}

func resolveEarlyTool(name string) (string, error) {
	path, err := trustedexec.Resolve(name)
	if err != nil {
		return "", fmt.Errorf("resolve required Windows To Go utility %s: %w", name, err)
	}
	return path, nil
}

func createSecureWorkDir() (string, error) {
	base := "/var/tmp"
	if info, err := os.Stat(base); err != nil || !info.IsDir() {
		base = os.TempDir()
	}
	workDir, err := os.MkdirTemp(base, "rufusarm64-wtg-")
	if err != nil {
		return "", fmt.Errorf("create Windows To Go workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return "", err
	}
	info, err := os.Stat(workDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		_ = os.RemoveAll(workDir)
		return "", errors.New("windows To Go workspace is not private")
	}
	return workDir, nil
}

func sendEvent(emit EventFunc, event Event) {
	if emit != nil {
		emit(event)
	}
}
