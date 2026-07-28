//go:build linux

package linuxmedia

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

// ISOImageCreateOptions binds one plain Linux ISOHybrid source to one exact
// target device and the final safety callback supplied by the privileged GUI
// helper.
type ISOImageCreateOptions struct {
	TargetSize        uint64
	ExpectedDeviceID  uint64
	ExpectedSource    sourcefile.Identity
	Architecture      string
	VolumeLabel       string
	WorkDirectory     string
	BeforeDestructive func(source *os.File) error
	ManifestMaxEntries int
	ManifestMaxBytes  uint64
}

// ISOImageCreateResult records the exact layout and verified source tree copied
// into the newly created writable FAT32 partition.
type ISOImageCreateResult struct {
	Layout       ISOImageLayout `json:"layout"`
	Manifest     Manifest       `json:"manifest"`
	SourceSHA256 string         `json:"source_sha256"`
	UEFIBootPath string         `json:"uefi_boot_path"`
	VolumeLabel  string         `json:"volume_label"`
}

// CreateISOImage creates a fresh GPT/UEFI/FAT32 USB and copies every accepted
// ISO file through the existing manifest verifier. It intentionally supports a
// narrower set than DD mode and refuses before erasure when FAT32, fallback
// UEFI, source stability, target identity, or capacity requirements are unmet.
func CreateISOImage(ctx context.Context, isoPath, devicePath string, opts ISOImageCreateOptions, emit PersistentEventFunc) (result ISOImageCreateResult, returnErr error) {
	completed := false
	defer func() {
		if completed && returnErr == nil {
			sendPersistent(emit, PersistentEvent{Stage: "complete", Message: "Linux ISO Image mode USB created and verified."})
		}
	}()
	if ctx == nil {
		return result, errors.New("ISO Image mode creation context is nil")
	}
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return result, errors.New("ISO Image mode creation requires an identity-bound source image")
	}
	label, err := normalizePersistentLabel(opts.VolumeLabel)
	if err != nil {
		return result, err
	}

	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return result, err
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, isoFile, false, "selected Linux ISO")
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
	targetChanged := false

	sourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
	switch {
	case leaseErr == nil:
		ctx = sourceLease.Context()
		sendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: "Holding the selected Linux ISO read-only with a kernel lease; one complete SHA-256 pass will authenticate the held bytes."})
		defer func() {
			heldErr := sourceLease.Check()
			if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
				message := "the selected Linux ISO was opened for writing during ISO Image mode analysis; nothing was erased"
				if targetChanged {
					message = "the selected Linux ISO was opened for writing while the USB was being created; the USB is incomplete and must be recreated"
				}
				heldErr = fmt.Errorf("%s: %w", message, heldErr)
			}
			closeErr := sourceLease.Close()
			if heldErr != nil || closeErr != nil {
				completed = false
			}
			returnErr = errors.Join(returnErr, heldErr, closeErr)
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		sourceLease = nil
		sendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 source verification.", leaseErr)})
	default:
		return result, fmt.Errorf("hold selected Linux ISO stable: %w", leaseErr)
	}

	initialHashMessage := "Hashing the selected Linux ISO once under the kernel source hold…"
	if sourceLease == nil {
		initialHashMessage = "Hashing the selected Linux ISO (conservative pass 1 of 3)…"
	}
	sourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", initialHashMessage)
	if err != nil {
		return result, fmt.Errorf("hash selected Linux ISO: %w", err)
	}

	for _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "mkfs.vfat", "fsck.vfat"} {
		if _, err := exec.LookPath(name); err != nil {
			return result, fmt.Errorf("required program %q is not installed", name)
		}
	}

	target, err := os.OpenFile(devicePath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, fmt.Errorf("open target for Linux ISO Image mode: %w", err)
	}
	targetLocked := false
	defer func() {
		returnErr = finishPersistentFile(returnErr, target, targetLocked, "Linux ISO Image mode target")
	}()
	if err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return result, err
	}
	if err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return result, fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	targetLocked = true
	stableTargetPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), target.Fd())
	targetInfo, err := target.Stat()
	if err != nil {
		return result, fmt.Errorf("stat ISO Image mode target: %w", err)
	}
	testTarget := targetInfo.Mode().IsRegular()
	if !testTarget && opts.ExpectedDeviceID == 0 {
		return result, errors.New("ISO Image mode requires an identity-bound target device")
	}
	if !testTarget && opts.BeforeDestructive == nil {
		return result, errors.New("ISO Image mode requires a final target-safety callback")
	}
	if opts.TargetSize == 0 {
		opts.TargetSize, err = persistentBlockDeviceSize(ctx, devicePath)
		if err != nil {
			return result, err
		}
	}
	if err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return result, err
	}
	sectorSize, err := persistentLogicalSectorSize(ctx, devicePath, testTarget)
	if err != nil {
		return result, err
	}

	workRoot := strings.TrimSpace(opts.WorkDirectory)
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-linux-iso-image-")
	if err != nil {
		return result, fmt.Errorf("create ISO Image mode workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("secure ISO Image mode workspace: %w", err)
	}
	if !testTarget {
		if err := safety.EnsurePathNotOnTarget(workDir, devicePath); err != nil {
			_ = os.RemoveAll(workDir)
			return result, fmt.Errorf("ISO Image mode workspace is unsafe: %w", err)
		}
	}
	isoMount := filepath.Join(workDir, "iso")
	bootMount := filepath.Join(workDir, "boot")
	for _, directory := range []string{isoMount, bootMount} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			_ = os.RemoveAll(workDir)
			return result, err
		}
	}
	mountedISO := false
	mountedBoot := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mountedBoot {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", bootMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup ISO Image mode FAT32 mount: %w", err))
			} else {
				mountedBoot = false
			}
		}
		if mountedISO {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", isoMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup ISO Image mode source mount: %w", err))
			} else {
				mountedISO = false
			}
		}
		if !mountedBoot && !mountedISO {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove ISO Image mode workspace: %w", err))
			}
		}
	}()

	sourceRoot := isoMount
	if testTarget && os.Getenv("RUFUS_TEST_ISO_ROOT") != "" {
		sourceRoot, err = resolveRoot(os.Getenv("RUFUS_TEST_ISO_ROOT"))
		if err != nil {
			return result, fmt.Errorf("resolve test ISO root: %w", err)
		}
	} else {
		sendPersistent(emit, PersistentEvent{Stage: "mount", Message: "Mounting the selected Linux ISO read-only…"})
		if err := runPersistent(ctx, emit, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, isoMount); err != nil {
			return result, fmt.Errorf("mount Linux ISO: %w", err)
		}
		mountedISO = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Hashing the complete ISO tree and checking UEFI/FAT32 compatibility before erasing the USB…"})
	manifest, err := Inspect(ctx, sourceRoot, Options{
		Architecture: opts.Architecture,
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
	layout, err := PlanISOImageLayout(opts.TargetSize, sectorSize, fat32Bytes)
	if err != nil {
		return result, err
	}
	result = ISOImageCreateResult{
		Layout:       layout,
		Manifest:     manifest,
		SourceSHA256: hex.EncodeToString(sourceDigest[:]),
		UEFIBootPath: manifest.UEFIBootPath,
		VolumeLabel:  label,
	}

	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return result, fmt.Errorf("confirm held Linux ISO before erasing the USB: %w", err)
		}
	} else {
		preDestructiveDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Rechecking the Linux ISO before erasing the USB (conservative pass 2 of 3)…")
		if err != nil {
			return result, err
		}
		if !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
			return result, errors.New("the selected Linux ISO changed during compatibility analysis; nothing was erased")
		}
	}
	checkTarget := func() error {
		if sourceLease != nil {
			if err := sourceLease.Check(); err != nil {
				return err
			}
		}
		if err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
			return err
		}
		return safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize)
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if opts.BeforeDestructive != nil {
		if err := opts.BeforeDestructive(isoFile); err != nil {
			return result, fmt.Errorf("target safety check: %w", err)
		}
	}

	targetChanged = true
	sendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout with one writable FAT32 UEFI partition…"})
	if err := runPersistent(ctx, emit, "wipefs", "--all", "--force", "--", stableTargetPath); err != nil {
		return result, err
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := WriteISOImageGPT(target, layout, label); err != nil {
		return result, fmt.Errorf("write ISO Image mode GPT: %w", err)
	}
	if err := persistentRereadPartitionTable(ctx, stableTargetPath, emit); err != nil {
		sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Warning: could not force an immediate partition-table reread: %v", err)})
	}
	if err := checkTarget(); err != nil {
		return result, err
	}

	partitionPath, err := isoImagePartitionPath(ctx, devicePath, layout.Partition, testTarget)
	if err != nil {
		return result, err
	}
	if err := unmountPersistentDeviceMounts(ctx, partitionPath); err != nil {
		return result, err
	}
	bootFile, err := openPersistentPartition(partitionPath, layout.Partition, opts.ExpectedDeviceID, testTarget)
	if err != nil {
		return result, fmt.Errorf("identity-bind ISO Image mode FAT32 partition: %w", err)
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, bootFile, true, "ISO Image mode FAT32 partition")
	}()
	bootFDPath := "/proc/self/fd/3"

	sendPersistent(emit, PersistentEvent{Stage: "format", Message: fmt.Sprintf("Formatting the writable UEFI partition as FAT32 (%s)…", label)})
	clusterSectors := fat32ClusterBytes / sectorSize
	if err := runPersistentFileUnlocked(ctx, emit, bootFile, "mkfs.vfat", "-F", "32", "-s", fmt.Sprintf("%d", clusterSectors), "-n", label, bootFDPath); err != nil {
		return result, fmt.Errorf("format ISO Image mode FAT32 partition: %w", err)
	}
	if err := unmountPersistentDeviceMounts(ctx, partitionPath); err != nil {
		return result, err
	}

	destinationRoot := bootMount
	if testTarget && os.Getenv("RUFUS_TEST_BOOT_ROOT") != "" {
		destinationRoot, err = resolveEmptyTestRoot(os.Getenv("RUFUS_TEST_BOOT_ROOT"))
		if err != nil {
			return result, err
		}
	} else {
		if err := runPersistentFile(ctx, emit, bootFile, "mount", "-t", "vfat", "-o", "rw,nosuid,nodev,noexec,umask=0077", "--", bootFDPath, bootMount); err != nil {
			return result, fmt.Errorf("mount ISO Image mode FAT32 partition: %w", err)
		}
		mountedBoot = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Copying and verifying the Linux ISO filesystem tree…", Total: manifest.TotalBytes})
	if err := CopyAndVerify(ctx, manifest, destinationRoot, CopyOptions{Event: func(event CopyEvent) {
		sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Copying and verifying the Linux ISO filesystem tree…", Path: event.Path, Done: event.Done, Total: event.Total})
	}}); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {
		return result, fmt.Errorf("sync ISO Image mode files: %w", err)
	}
	if mountedBoot {
		if err := runPersistent(ctx, emit, "umount", "--", bootMount); err != nil {
			return result, fmt.Errorf("unmount ISO Image mode FAT32 partition: %w", err)
		}
		mountedBoot = false
	}
	if err := bootFile.Sync(); err != nil {
		return result, fmt.Errorf("sync ISO Image mode FAT32 partition: %w", err)
	}
	if err := runPersistentFile(ctx, emit, bootFile, "blockdev", "--flushbufs", bootFDPath); err != nil && !testTarget {
		return result, fmt.Errorf("flush ISO Image mode FAT32 partition buffers: %w", err)
	}
	sendPersistent(emit, PersistentEvent{Stage: "check", Message: "Checking the FAT32 filesystem after the verified copy…"})
	if err := runPersistentFile(ctx, emit, bootFile, "fsck.vfat", "-n", bootFDPath); err != nil {
		return result, fmt.Errorf("ISO Image mode FAT32 filesystem check failed: %w", err)
	}
	if err := verifyPersistentPartitionFile(bootFile, layout.Partition, opts.ExpectedDeviceID, testTarget); err != nil {
		return result, fmt.Errorf("revalidate ISO Image mode FAT32 partition: %w", err)
	}

	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return result, fmt.Errorf("confirm held Linux ISO after copying: %w", err)
		}
	} else {
		postDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Checking that the Linux ISO stayed unchanged (conservative pass 3 of 3)…")
		if err != nil {
			return result, err
		}
		if !bytes.Equal(sourceDigest[:], postDigest[:]) {
			return result, errors.New("the selected Linux ISO changed while the USB was being created; recreate the USB")
		}
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "blockdev", "--flushbufs", stableTargetPath); err != nil && !testTarget {
		return result, fmt.Errorf("flush ISO Image mode USB buffers: %w", err)
	}
	if mountedISO {
		if err := runPersistent(ctx, emit, "umount", "--", isoMount); err != nil {
			return result, err
		}
		mountedISO = false
	}
	completed = true
	return result, nil
}

func isoImagePartitionPath(ctx context.Context, devicePath string, layout PartitionLayout, testTarget bool) (string, error) {
	if testTarget {
		path := strings.TrimSpace(os.Getenv("RUFUS_TEST_BOOT_PARTITION"))
		if path == "" {
			return "", errors.New("test ISO Image mode partition is not configured")
		}
		return path, nil
	}
	return waitPersistentPartition(ctx, devicePath, layout, 45*time.Second)
}
