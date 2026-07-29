//go:build linux

package linuxmedia

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const minimumExtractedDiskSize = uint64(128 * 1024 * 1024)

type ExtractedLayout struct {
	SectorSize uint64          `json:"sector_size"`
	TargetSize uint64          `json:"target_size"`
	Partition  PartitionLayout `json:"partition"`
}

type ExtractedCreateOptions struct {
	TargetSize         uint64
	ExpectedDeviceID   uint64
	ExpectedSource     sourcefile.Identity
	Architecture       string
	VolumeLabel        string
	PartitionScheme    string
	ClusterSize        uint64
	WorkDirectory      string
	BeforeDestructive  func(source *os.File) error
	ManifestMaxEntries int
	ManifestMaxBytes   uint64
}

type ExtractedCreateResult struct {
	Layout          ExtractedLayout `json:"layout"`
	Manifest        Manifest        `json:"manifest"`
	SourceSHA256    string          `json:"source_sha256"`
	UEFIBootPath    string          `json:"uefi_boot_path"`
	PartitionScheme string          `json:"partition_scheme"`
	ClusterSize     uint64          `json:"cluster_size"`
}

// PlanExtractedLayout creates a conventional one-partition FAT32 MBR layout for
// UEFI Linux media. The 1 MiB offset leaves conventional boot-code/alignment
// space while the remaining target capacity stays available as writable FAT32.
func PlanExtractedLayout(targetSize, sectorSize, copiedBytes uint64) (ExtractedLayout, error) {
	if targetSize > uint64(math.MaxInt64) {
		return ExtractedLayout{}, errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumExtractedDiskSize {
		return ExtractedLayout{}, fmt.Errorf("target is too small for ISO Image mode: need at least %d bytes", minimumExtractedDiskSize)
	}
	if sectorSize < 512 || sectorSize > fat32ClusterBytes || sectorSize&(sectorSize-1) != 0 {
		return ExtractedLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return ExtractedLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if copiedBytes == 0 {
		return ExtractedLayout{}, errors.New("linux media tree is empty")
	}
	startBytes := alignLayout(layoutAlignment, sectorSize)
	if startBytes >= targetSize {
		return ExtractedLayout{}, errors.New("target has no usable partition space after alignment")
	}
	partitionBytes := (targetSize - startBytes) / sectorSize * sectorSize
	startSectors := startBytes / sectorSize
	partitionSectors := partitionBytes / sectorSize
	if startSectors > uint64(^uint32(0)) || partitionSectors > uint64(^uint32(0)) {
		return ExtractedLayout{}, errors.New("target is too large for ISO Image mode MBR; use DD Image mode")
	}
	margin := copiedBytes / 20
	if margin < 64*1024*1024 {
		margin = 64 * 1024 * 1024
	}
	if copiedBytes > ^uint64(0)-margin || copiedBytes+margin > partitionBytes {
		return ExtractedLayout{}, fmt.Errorf("target has %d usable bytes but the verified media tree needs at least %d", partitionBytes, copiedBytes+margin)
	}
	return ExtractedLayout{
		SectorSize: sectorSize,
		TargetSize: targetSize,
		Partition: PartitionLayout{
			Number:     1,
			StartBytes: startBytes,
			SizeBytes:  partitionBytes,
		},
	}, nil
}

// WriteExtractedMBR writes and verifies a single active FAT32-LBA partition.
func WriteExtractedMBR(target layoutTarget, layout ExtractedLayout) error {
	if target == nil {
		return errors.New("nil ISO Image mode target")
	}
	if err := validateExtractedLayout(layout); err != nil {
		return err
	}
	sector := make([]byte, layout.SectorSize)
	if _, err := rand.Read(sector[440:444]); err != nil {
		return fmt.Errorf("generate MBR disk signature: %w", err)
	}
	entry := sector[446:462]
	entry[0] = 0x80
	entry[1], entry[2], entry[3] = 0xfe, 0xff, 0xff
	entry[4] = 0x0c
	entry[5], entry[6], entry[7] = 0xfe, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], uint32(layout.Partition.StartBytes/layout.SectorSize))
	binary.LittleEndian.PutUint32(entry[12:16], uint32(layout.Partition.SizeBytes/layout.SectorSize))
	sector[510], sector[511] = 0x55, 0xaa
	if _, err := target.WriteAt(sector, 0); err != nil {
		return fmt.Errorf("write ISO Image mode MBR: %w", err)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync ISO Image mode MBR: %w", err)
	}
	readback := make([]byte, layout.SectorSize)
	if _, err := target.ReadAt(readback, 0); err != nil {
		return fmt.Errorf("read back ISO Image mode MBR: %w", err)
	}
	if !bytes.Equal(readback, sector) {
		return errors.New("ISO Image mode MBR readback mismatch")
	}
	return nil
}

func validateExtractedLayout(layout ExtractedLayout) error {
	if layout.TargetSize < minimumExtractedDiskSize || layout.TargetSize > uint64(math.MaxInt64) ||
		layout.SectorSize < 512 || layout.SectorSize > fat32ClusterBytes || layout.SectorSize&(layout.SectorSize-1) != 0 ||
		layout.TargetSize%layout.SectorSize != 0 {
		return errors.New("ISO Image mode layout has invalid target geometry")
	}
	part := layout.Partition
	if part.Number != 1 || part.StartBytes%layout.SectorSize != 0 || part.SizeBytes == 0 || part.SizeBytes%layout.SectorSize != 0 ||
		part.StartBytes >= layout.TargetSize || part.SizeBytes > layout.TargetSize-part.StartBytes {
		return errors.New("ISO Image mode layout has an invalid partition extent")
	}
	start := part.StartBytes / layout.SectorSize
	size := part.SizeBytes / layout.SectorSize
	if start > uint64(^uint32(0)) || size > uint64(^uint32(0)) {
		return errors.New("ISO Image mode layout exceeds MBR addressing")
	}
	return nil
}

// CreateExtracted implements Rufus-style ISO Image mode for a bounded ARM64
// UEFI/FAT32-compatible ISOHybrid media tree. It authenticates the held source,
// completes every compatibility and capacity check before erasure, copies each
// file transactionally, hashes it back from the USB, checks FAT32, and flushes
// the physical device before success.
func CreateExtracted(ctx context.Context, isoPath, devicePath string, opts ExtractedCreateOptions, emit PersistentEventFunc) (result ExtractedCreateResult, returnErr error) {
	if opts.ExpectedSource == (sourcefile.Identity{}) {
		return result, errors.New("ISO Image mode requires an identity-bound source image")
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
				message := "the selected Linux image was opened for writing during ISO Image mode preflight; nothing was erased"
				if targetChanged {
					message = "the selected Linux image was opened for writing while ISO Image mode was creating the USB; the USB is incomplete and must be recreated"
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
	for _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "mkfs.vfat", "fsck.vfat"} {
		if _, err := exec.LookPath(name); err != nil {
			return result, fmt.Errorf("required program %q is not installed", name)
		}
	}

	target, err := os.OpenFile(devicePath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, fmt.Errorf("open target for ISO Image mode: %w", err)
	}
	targetLocked := false
	defer func() {
		returnErr = finishPersistentFile(returnErr, target, targetLocked, "ISO Image mode target")
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
	label, err := normalizePersistentLabel(opts.VolumeLabel)
	if err != nil {
		return result, err
	}
	partitionScheme, err := normalizeExtractedPartitionScheme(opts.PartitionScheme)
	if err != nil {
		return result, err
	}
	clusterBytes, err := normalizeExtractedClusterSize(opts.ClusterSize, sectorSize)
	if err != nil {
		return result, err
	}

	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-linux-iso-")
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
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup ISO Image mode USB mount: %w", err))
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

	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: fmt.Sprintf("Checking ISO Image mode %s/UEFI/FAT32, cluster, filename, and capacity compatibility…", strings.ToUpper(partitionScheme))})
	manifest, err := Inspect(ctx, sourceRoot, Options{
		Architecture: opts.Architecture,
		RequireUEFI:  true,
		RequireFAT32: true,
		MaxEntries:   opts.ManifestMaxEntries,
		MaxBytes:     opts.ManifestMaxBytes,
	})
	if err != nil {
		return result, fmt.Errorf("ISO Image mode is not supported for this image: %w", err)
	}
	fat32Bytes, err := EstimateFAT32BytesForCluster(manifest, clusterBytes)
	if err != nil {
		return result, err
	}
	layout, err := PlanExtractedLayoutForScheme(opts.TargetSize, sectorSize, fat32Bytes, partitionScheme)
	if err != nil {
		return result, err
	}
	if err := validateExtractedFAT32Capacity(layout.Partition.SizeBytes, clusterBytes); err != nil {
		return result, err
	}
	result = ExtractedCreateResult{
		Layout:          layout,
		Manifest:        manifest,
		SourceSHA256:    hex.EncodeToString(sourceDigest[:]),
		UEFIBootPath:    manifest.UEFIBootPath,
		PartitionScheme: partitionScheme,
		ClusterSize:     clusterBytes,
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
			return result, errors.New("the selected Linux image changed during ISO Image mode preflight; nothing was erased")
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
	sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Creating one writable %s/UEFI/FAT32 partition for ISO Image mode…", strings.ToUpper(partitionScheme))})
	if err := runPersistent(ctx, emit, "wipefs", "--all", "--force", "--", stableTargetPath); err != nil {
		return result, err
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := WriteExtractedPartitionTable(target, layout, partitionScheme, label); err != nil {
		return result, err
	}
	if err := persistentRereadPartitionTable(ctx, stableTargetPath, emit); err != nil {
		sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Warning: could not force an immediate partition-table reread: %v", err)})
	}
	if err := checkTarget(); err != nil {
		return result, err
	}

	partitionPath := ""
	if testTarget {
		partitionPath = os.Getenv("RUFUS_TEST_ISO_PARTITION")
		if partitionPath == "" {
			return result, errors.New("test ISO Image mode partition is not configured")
		}
	} else {
		partitionPath, err = waitPersistentPartition(ctx, devicePath, layout.Partition, 45*time.Second)
		if err != nil {
			return result, err
		}
	}
	if err := unmountPersistentDeviceMounts(ctx, partitionPath); err != nil {
		return result, err
	}
	partitionFile, err := openPersistentPartition(partitionPath, layout.Partition, opts.ExpectedDeviceID, testTarget)
	if err != nil {
		return result, fmt.Errorf("identity-bind ISO Image mode partition: %w", err)
	}
	defer func() {
		returnErr = finishPersistentFile(returnErr, partitionFile, true, "ISO Image mode partition")
	}()
	partitionFDPath := "/proc/self/fd/3"
	clusterSectors := clusterBytes / sectorSize
	sendPersistent(emit, PersistentEvent{Stage: "format", Message: fmt.Sprintf("Formatting the ISO Image mode partition as FAT32 (%s)…", label)})
	if err := runPersistentFileUnlocked(ctx, emit, partitionFile, "mkfs.vfat", "-F", "32", "-s", strconv.FormatUint(clusterSectors, 10), "-n", label, partitionFDPath); err != nil {
		return result, fmt.Errorf("format ISO Image mode partition: %w", err)
	}
	if err := unmountPersistentDeviceMounts(ctx, partitionPath); err != nil {
		return result, err
	}

	destinationRoot := usbMount
	if testTarget && os.Getenv("RUFUS_TEST_ISO_DESTINATION") != "" {
		destinationRoot, err = resolveEmptyTestRoot(os.Getenv("RUFUS_TEST_ISO_DESTINATION"))
		if err != nil {
			return result, err
		}
	} else {
		if err := runPersistentFile(ctx, emit, partitionFile, "mount", "-t", "vfat", "-o", "rw,nosuid,nodev,noexec,umask=0077", "--", partitionFDPath, usbMount); err != nil {
			return result, fmt.Errorf("mount ISO Image mode partition: %w", err)
		}
		mountedUSB = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Extracting and verifying the ISO media tree…", Total: manifest.TotalBytes})
	if err := CopyAndVerify(ctx, manifest, destinationRoot, CopyOptions{Event: func(event CopyEvent) {
		sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Extracting and verifying the ISO media tree…", Path: event.Path, Done: event.Done, Total: event.Total})
	}}); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {
		return result, fmt.Errorf("sync ISO Image mode files: %w", err)
	}
	if mountedUSB {
		if err := runPersistent(ctx, emit, "umount", "--", usbMount); err != nil {
			return result, fmt.Errorf("unmount ISO Image mode partition: %w", err)
		}
		mountedUSB = false
	}
	if err := partitionFile.Sync(); err != nil {
		return result, fmt.Errorf("sync ISO Image mode partition: %w", err)
	}
	if err := runPersistentFile(ctx, emit, partitionFile, "blockdev", "--flushbufs", partitionFDPath); err != nil && !testTarget {
		return result, fmt.Errorf("flush ISO Image mode partition: %w", err)
	}
	sendPersistent(emit, PersistentEvent{Stage: "check", Message: "Checking the FAT32 filesystem…"})
	if err := runPersistentFile(ctx, emit, partitionFile, "fsck.vfat", "-n", partitionFDPath); err != nil {
		return result, fmt.Errorf("ISO Image mode FAT32 check failed: %w", err)
	}
	if err := verifyPersistentPartitionFile(partitionFile, layout.Partition, opts.ExpectedDeviceID, testTarget); err != nil {
		return result, fmt.Errorf("revalidate ISO Image mode partition: %w", err)
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
			return result, errors.New("the selected Linux image changed while ISO Image mode was creating the USB; recreate the USB")
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
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: fmt.Sprintf("ISO Image mode USB created and verified (%s/UEFI/FAT32, %d-byte clusters).", strings.ToUpper(partitionScheme), clusterBytes)})
	return result, nil
}
