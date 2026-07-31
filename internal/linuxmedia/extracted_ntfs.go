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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

// ExtractedNTFSCreateResult is the exact evidence returned by the separate
// guarded Linux NTFS/UEFI:NTFS creation path.
type ExtractedNTFSCreateResult struct {
	Plan           ExtractedMediaPlan `json:"plan"`
	Manifest       Manifest           `json:"manifest"`
	SourceSHA256   string             `json:"source_sha256"`
	UEFIBootPath   string             `json:"uefi_boot_path"`
	UEFINTFSPath   string             `json:"uefi_ntfs_path"`
	UEFINTFSSHA256 string             `json:"uefi_ntfs_sha256"`
	UEFINTFSSize   uint64             `json:"uefi_ntfs_size"`
	DataPartition  string             `json:"data_partition"`
	BootPartition  string             `json:"boot_partition"`
}

// CreateExtractedNTFS implements the privileged NTFS half of Linux ISO Image
// mode without changing the existing FAT32 or DD paths. Every source, target,
// filesystem, layout, and UEFI:NTFS asset check completes before erasure.
func CreateExtractedNTFS(ctx context.Context, isoPath, devicePath string, opts ExtractedCreateOptions, emit PersistentEventFunc) (result ExtractedNTFSCreateResult, returnErr error) {
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return result, errors.New("NTFS ISO Image mode requires an identity-bound source image")
	}
	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return result, err
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, isoFile, false, "selected Linux image")
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
	targetChanged := false

	sourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
	switch {
	case leaseErr == nil:
		ctx = sourceLease.Context()
		sendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: "Holding the selected Linux image read-only with a Linux kernel lease; one complete SHA-256 pass will authenticate the held bytes."})
		defer func() {
			heldErr := sourceLease.Check()
			if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
				message := "the selected Linux image was opened for writing during NTFS ISO Image mode preflight; nothing was erased"
				if targetChanged {
					message = "the selected Linux image was opened for writing while NTFS ISO Image mode was creating the USB; the USB is incomplete and must be recreated"
				}
				heldErr = fmt.Errorf("%s: %w", message, heldErr)
			}
			returnErr = errors.Join(returnErr, heldErr, sourceLease.Close())
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		sourceLease = nil
		sendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 source verification.", leaseErr)})
	default:
		return result, fmt.Errorf("hold selected Linux image stable: %w", leaseErr)
	}

	initialHashMessage := "Hashing the selected Linux image once under the kernel source hold…"
	if sourceLease == nil {
		initialHashMessage = "Hashing the selected Linux image (conservative pass 1 of 3)…"
	}
	sourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", initialHashMessage)
	if err != nil {
		return result, fmt.Errorf("hash selected Linux image: %w", err)
	}
	for _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "ntfsfix"} {
		if _, err := exec.LookPath(name); err != nil {
			return result, fmt.Errorf("required program %q is not installed", name)
		}
	}
	ntfsFormatter, err := extractedNTFSFormatterExecutable()
	if err != nil {
		return result, err
	}

	target, err := os.OpenFile(devicePath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, fmt.Errorf("open target for NTFS ISO Image mode: %w", err)
	}
	targetLocked := false
	defer func() {
		returnErr = finishPersistentFile(returnErr, target, targetLocked, "NTFS ISO Image mode target")
	}()
	if err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return result, err
	}
	if err := acquireExtractedTargetLock(ctx, target, devicePath); err != nil {
		return result, err
	}
	targetLocked = true
	stableTargetPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), target.Fd())
	targetInfo, err := target.Stat()
	if err != nil {
		return result, fmt.Errorf("stat NTFS ISO Image mode target: %w", err)
	}
	testTarget := targetInfo.Mode().IsRegular()
	if !testTarget && opts.ExpectedDeviceID == 0 {
		return result, errors.New("NTFS ISO Image mode requires an identity-bound target device")
	}
	if !testTarget && opts.BeforeDestructive == nil {
		return result, errors.New("NTFS ISO Image mode requires a final target-safety callback")
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

	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-linux-iso-ntfs-")
	if err != nil {
		return result, fmt.Errorf("create NTFS ISO Image mode workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("secure NTFS ISO Image mode workspace: %w", err)
	}
	if !testTarget {
		if err := safety.EnsurePathNotOnTarget(workDir, devicePath); err != nil {
			_ = os.RemoveAll(workDir)
			return result, fmt.Errorf("NTFS ISO Image mode workspace is unsafe: %w", err)
		}
	}
	isoMount := filepath.Join(workDir, "iso")
	usbMount := filepath.Join(workDir, "usb")
	for _, directory := range []string{isoMount, usbMount} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			_ = os.RemoveAll(workDir)
			return result, err
		}
	}
	mountedISO := false
	mountedUSB := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mountedUSB {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", usbMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup NTFS ISO Image mode USB mount: %w", err))
			} else {
				mountedUSB = false
			}
		}
		if mountedISO {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", isoMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup Linux image mount: %w", err))
			} else {
				mountedISO = false
			}
		}
		if !mountedUSB && !mountedISO {
			returnErr = errors.Join(returnErr, os.RemoveAll(workDir))
		}
	}()

	sourceRoot := isoMount
	if testTarget && os.Getenv("RUFUS_TEST_ISO_ROOT") != "" {
		sourceRoot, err = resolveRoot(os.Getenv("RUFUS_TEST_ISO_ROOT"))
		if err != nil {
			return result, fmt.Errorf("resolve test Linux image root: %w", err)
		}
	} else {
		sendPersistent(emit, PersistentEvent{Stage: "mount", Message: "Mounting the selected Linux image read-only…"})
		if err := runPersistent(ctx, emit, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, isoMount); err != nil {
			return result, fmt.Errorf("mount Linux image: %w", err)
		}
		mountedISO = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Checking ISO Image mode UEFI/NTFS names, asset, cluster, layout, and capacity compatibility…"})
	prepared, err := prepareExtractedManifest(ctx, isoFile, sourceRoot, workDir, Options{
		Architecture: opts.Architecture,
		RequireUEFI:  true,
		RequireFAT32: false,
		MaxEntries:   opts.ManifestMaxEntries,
		MaxBytes:     opts.ManifestMaxBytes,
	}, testTarget && os.Getenv("RUFUS_TEST_ISO_ROOT") != "", emit)
	if err != nil {
		return result, fmt.Errorf("NTFS ISO Image mode is not supported for this image: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, prepared.Close())
	}()
	manifest := prepared.Manifest
	plan, err := PlanExtractedMedia(manifest, "ntfs", opts.PartitionScheme, opts.VolumeLabel, opts.ClusterSize, opts.TargetSize, sectorSize)
	if err != nil {
		return result, err
	}
	asset, err := uefintfs.Locate()
	if err != nil {
		return result, err
	}
	if asset.Size() != plan.UEFINTFSImageSize || asset.SHA256() != plan.UEFINTFSImageSHA256 {
		return result, errors.New("verified UEFI:NTFS asset does not match the reviewed Linux media plan")
	}
	sharedLayout, err := uefintfs.PlanLayout(plan.PartitionScheme, plan.TargetSize, plan.SectorSize)
	if err != nil {
		return result, err
	}
	if plan.Boot == nil || plan.Data.StartBytes != sharedLayout.Data.StartBytes || plan.Data.SizeBytes != sharedLayout.Data.SizeBytes ||
		plan.Boot.StartBytes != sharedLayout.Boot.StartBytes || plan.Boot.SizeBytes != sharedLayout.Boot.SizeBytes {
		return result, errors.New("NTFS ISO Image mode plan disagrees with shared UEFI:NTFS geometry")
	}
	result = ExtractedNTFSCreateResult{
		Plan:           plan,
		Manifest:       manifest,
		SourceSHA256:   hex.EncodeToString(sourceDigest[:]),
		UEFIBootPath:   manifest.UEFIBootPath,
		UEFINTFSPath:   asset.Path(),
		UEFINTFSSHA256: asset.SHA256(),
		UEFINTFSSize:   asset.Size(),
	}

	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return result, fmt.Errorf("confirm held Linux image before erasing the USB: %w", err)
		}
	} else {
		preDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Rechecking the Linux image before erasing the USB (conservative pass 2 of 3)…")
		if err != nil {
			return result, err
		}
		if !bytes.Equal(sourceDigest[:], preDigest[:]) {
			return result, errors.New("the selected Linux image changed during NTFS ISO Image mode preflight; nothing was erased")
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
	sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Creating %s/UEFI NTFS data and verified UEFI:NTFS boot partitions…", strings.ToUpper(plan.PartitionScheme))})
	if err := runPersistent(ctx, emit, "wipefs", "--all", "--force", "--", stableTargetPath); err != nil {
		return result, err
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := uefintfs.WriteLayout(target, sharedLayout, plan.VolumeLabel); err != nil {
		return result, err
	}
	if err := uefintfs.WriteAndVerify(target, asset, uefintfs.Partition{StartBytes: sharedLayout.Boot.StartBytes, SizeBytes: sharedLayout.Boot.SizeBytes}); err != nil {
		return result, err
	}
	if err := persistentRereadPartitionTable(ctx, stableTargetPath, emit); err != nil {
		sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Warning: could not force an immediate partition-table reread: %v", err)})
	}
	if err := checkTarget(); err != nil {
		return result, err
	}

	dataPartitionPath := ""
	bootPartitionPath := ""
	if testTarget {
		dataPartitionPath = os.Getenv("RUFUS_TEST_ISO_PARTITION")
		bootPartitionPath = os.Getenv("RUFUS_TEST_ISO_BOOT_PARTITION")
		if dataPartitionPath == "" || bootPartitionPath == "" {
			return result, errors.New("test NTFS ISO Image mode data and boot partitions are not configured")
		}
	} else {
		dataPartitionPath, err = waitPersistentPartition(ctx, devicePath, plan.Data, 45*time.Second)
		if err != nil {
			return result, err
		}
		bootPartitionPath, err = waitPersistentPartition(ctx, devicePath, *plan.Boot, 45*time.Second)
		if err != nil {
			return result, err
		}
	}
	result.DataPartition = dataPartitionPath
	result.BootPartition = bootPartitionPath
	for _, partitionPath := range []string{dataPartitionPath, bootPartitionPath} {
		if err := unmountPersistentDeviceMounts(ctx, partitionPath); err != nil {
			return result, err
		}
	}
	if err := uefintfs.VerifyPartitionPath(bootPartitionPath, asset); err != nil {
		return result, err
	}

	dataPartitionFile, err := openPersistentPartition(dataPartitionPath, plan.Data, opts.ExpectedDeviceID, testTarget)
	if err != nil {
		return result, fmt.Errorf("identity-bind NTFS ISO Image mode data partition: %w", err)
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, dataPartitionFile, true, "NTFS ISO Image mode data partition")
	}()
	partitionFDPath := "/proc/self/fd/3"
	mkfsArgs := []string{"-F", "-Q", "-L", plan.VolumeLabel, "-c", strconv.FormatUint(plan.ClusterSize, 10), partitionFDPath}
	sendPersistent(emit, PersistentEvent{Stage: "format", Message: fmt.Sprintf("Formatting the ISO Image mode data partition as NTFS (%s)…", plan.VolumeLabel)})
	if err := runPersistentFileUnlocked(ctx, emit, dataPartitionFile, ntfsFormatter, mkfsArgs...); err != nil {
		return result, fmt.Errorf("format NTFS ISO Image mode partition: %w", err)
	}
	if err := unmountPersistentDeviceMounts(ctx, dataPartitionPath); err != nil {
		return result, err
	}

	destinationRoot := usbMount
	if testTarget && os.Getenv("RUFUS_TEST_ISO_DESTINATION") != "" {
		destinationRoot, err = resolveEmptyTestRoot(os.Getenv("RUFUS_TEST_ISO_DESTINATION"))
		if err != nil {
			return result, err
		}
	} else {
		if err := runPersistentFile(ctx, emit, dataPartitionFile, "mount", "-o", "rw,nosuid,nodev,noexec,umask=0077", "--", partitionFDPath, usbMount); err != nil {
			return result, fmt.Errorf("mount NTFS ISO Image mode partition: %w", err)
		}
		mountedUSB = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Extracting and verifying the ISO media tree to NTFS…", Total: manifest.TotalBytes})
	if err := CopyAndVerify(ctx, manifest, destinationRoot, CopyOptions{Event: func(event CopyEvent) {
		sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Extracting and verifying the ISO media tree to NTFS…", Path: event.Path, Done: event.Done, Total: event.Total})
	}}); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {
		return result, fmt.Errorf("sync NTFS ISO Image mode files: %w", err)
	}
	if mountedUSB {
		if err := runPersistent(ctx, emit, "umount", "--", usbMount); err != nil {
			return result, fmt.Errorf("unmount NTFS ISO Image mode partition: %w", err)
		}
		mountedUSB = false
	}
	if err := dataPartitionFile.Sync(); err != nil {
		return result, fmt.Errorf("sync NTFS ISO Image mode partition: %w", err)
	}
	if err := runPersistentFile(ctx, emit, dataPartitionFile, "blockdev", "--flushbufs", partitionFDPath); err != nil && !testTarget {
		return result, fmt.Errorf("flush NTFS ISO Image mode partition: %w", err)
	}
	sendPersistent(emit, PersistentEvent{Stage: "check", Message: "Checking the NTFS filesystem without repair…"})
	if err := runPersistentFile(ctx, emit, dataPartitionFile, "ntfsfix", "-n", partitionFDPath); err != nil {
		return result, fmt.Errorf("NTFS ISO Image mode filesystem check failed: %w", err)
	}
	if err := verifyPersistentPartitionFile(dataPartitionFile, plan.Data, opts.ExpectedDeviceID, testTarget); err != nil {
		return result, fmt.Errorf("revalidate NTFS ISO Image mode data partition: %w", err)
	}
	if err := uefintfs.VerifyPartitionPath(bootPartitionPath, asset); err != nil {
		return result, fmt.Errorf("revalidate UEFI:NTFS boot partition: %w", err)
	}

	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return result, fmt.Errorf("confirm held Linux image after copying: %w", err)
		}
	} else {
		postDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Checking that the Linux image stayed unchanged (conservative pass 3 of 3)…")
		if err != nil {
			return result, err
		}
		if !bytes.Equal(sourceDigest[:], postDigest[:]) {
			return result, errors.New("the selected Linux image changed while NTFS ISO Image mode was creating the USB; recreate the USB")
		}
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "blockdev", "--flushbufs", stableTargetPath); err != nil && !testTarget {
		return result, fmt.Errorf("flush NTFS ISO Image mode USB buffers: %w", err)
	}
	if mountedISO {
		if err := runPersistent(ctx, emit, "umount", "--", isoMount); err != nil {
			return result, err
		}
		mountedISO = false
	}
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: fmt.Sprintf("ISO Image mode USB created and verified (%s/UEFI/NTFS with verified UEFI:NTFS, %d-byte clusters).", strings.ToUpper(plan.PartitionScheme), plan.ClusterSize)})
	return result, nil
}

func extractedNTFSFormatterExecutable() (string, error) {
	for _, name := range []string{"mkfs.ntfs", "mkntfs"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("NTFS support requires mkfs.ntfs or mkntfs from the 'ntfs-3g' package")
}
