//go:build linux

// Package windowsmedia creates Windows installation USB media. FAT32 media
// use the firmware-native UEFI path and split oversized WIM/ESD payloads.
// NTFS UEFI media use Rufus's small FAT UEFI:NTFS compatibility partition.
// MBR media can also install the Windows BOOTMGR BIOS/CSM MBR and PBR code for
// x86 and x86-64 installation ISOs.
package windowsmedia

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const (
	fat32MaxFileSize      = uint64(4*1024*1024*1024 - 1)
	copyBufferSize        = 4 * 1024 * 1024
	minimumFreeMargin     = uint64(256 * 1024 * 1024)
	splitPartMiB          = "3500"
	bundledWimlibPath     = "/usr/lib/rufusarm64/wimlib-imagex"
	bundledUEFINTFSPath   = "/usr/lib/rufusarm64/uefi-ntfs.img"
	uefiNTFSImageSHA256   = "72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e"
	rufusDriverMarkerName = "RUFUSARM64.DRV"
)

var rufusDriverMarker = []byte("RufusArm64 Windows PE driver source\r\n")

// Options controls creation and post-write verification.
type Options struct {
	TargetSize        uint64
	Verify            bool
	ExpectedDeviceID  uint64
	ExpectedSource    sourcefile.Identity
	RequireARM64      bool
	VolumeLabel       string
	PartitionScheme   string
	TargetSystem      string
	Filesystem        string
	ClusterSize       uint64
	DriverFolder      string
	DBXPath           string
	FullFormat        bool
	BadBlockCheck     bool
	Customizations    windowsconfig.Options
	BeforeDestructive func(source *os.File) error
}

// Event is a progress or status update suitable for a terminal or GUI.
type Event struct {
	Stage   string
	Message string
	Done    uint64
	Total   uint64
}

type EventFunc func(Event)

type mediaPlan struct {
	InstallPath        string
	InstallRelative    string
	InstallSize        uint64
	NeedsSplit         bool
	SplitFiles         []string
	ExistingSplitFiles []string
	SplitBytes         uint64
	Architecture       string
	HasARM64           bool
	HasX64             bool
	HasX86             bool
	HasBootmgr         bool
	OtherBytes         uint64
	CopyBytes          uint64
	RequiredBytes      uint64
	ExistingAnswerPath string
	ExistingAnswerSize uint64
	AnswerFile         []byte
	Filesystem         string
	DriverFolder       string
	DriverBytes        uint64
}

// Create destroys devicePath and creates Windows installation media from
// isoPath using a validated GPT/MBR and FAT32/NTFS layout. The caller must
// already have applied whole-disk and system-disk safety policy. Create performs
// capacity, architecture, split-image, and identity checks before touching the
// target partition table.
func Create(ctx context.Context, isoPath, devicePath string, opts Options, emit EventFunc) (returnErr error) {
	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = finishWindowsMediaFile(returnErr, isoFile, false, "selected Windows ISO")
	}()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
	targetChanged := false

	sourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
	switch {
	case leaseErr == nil:
		ctx = sourceLease.Context()
		send(emit, Event{Stage: "source_hold", Message: "Holding the selected Windows ISO read-only with a Linux kernel lease; one complete SHA-256 pass will authenticate the held bytes."})
		defer func() {
			heldErr := sourceLease.Check()
			if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
				message := "the selected Windows ISO was opened for writing while media preparation was in progress; nothing was erased"
				if targetChanged {
					message = "the selected Windows ISO was opened for writing while USB creation was in progress; the USB is incomplete and must be recreated"
				}
				heldErr = fmt.Errorf("%s: %w", message, heldErr)
			}
			returnErr = errors.Join(returnErr, heldErr, sourceLease.Close())
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		sourceLease = nil
		send(emit, Event{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 source verification.", leaseErr)})
	default:
		return fmt.Errorf("hold selected Windows ISO stable: %w", leaseErr)
	}

	hashPinnedISO := func(stage, message string) ([sha256.Size]byte, error) {
		lastEmit := time.Time{}
		digest, hashErr := sourcefile.SHA256Open(ctx, isoFile, func(done, total uint64) {
			now := time.Now()
			if done == total || now.Sub(lastEmit) >= 200*time.Millisecond {
				lastEmit = now
				send(emit, Event{Stage: stage, Message: message, Done: done, Total: total})
			}
		})
		if hashErr != nil {
			return digest, hashErr
		}
		if err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
			return digest, err
		}
		return digest, nil
	}

	// Authenticate the exact ISO bytes once. A held Linux read lease excludes
	// conflicting writers for the rest of the operation. Filesystems that cannot
	// provide that hold retain the existing three-pass digest comparison.
	initialHashMessage := "Hashing the selected Windows ISO once under the kernel source hold…"
	if sourceLease == nil {
		initialHashMessage = "Hashing the selected Windows ISO (conservative pass 1 of 3)…"
	}
	sourceDigest, err := hashPinnedISO("hash_source", initialHashMessage)
	if err != nil {
		return fmt.Errorf("hash selected Windows ISO: %w", err)
	}

	for _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required program %q is not installed", name)
		}
	}

	lock, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open target for locking: %w", err)
	}
	lockHeld := false
	defer func() {
		returnErr = finishWindowsMediaFile(returnErr, lock, lockHeld, "Windows media target")
	}()
	if err := safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	lockHeld = true

	workDir, err := createWorkDir()
	if err != nil {
		return err
	}
	if err := safety.EnsurePathNotOnTarget(workDir, devicePath); err != nil {
		_ = os.RemoveAll(workDir)
		return fmt.Errorf("temporary workspace is unsafe: %w", err)
	}
	isoMount := filepath.Join(workDir, "iso")
	usbMount := filepath.Join(workDir, "usb")
	splitDir := filepath.Join(workDir, "split")
	mountedISO := false
	mountedUSB := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mountedUSB {
			if err := runQuiet(cleanupCtx, "umount", "--", usbMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup USB mount %s: %w", usbMount, err))
			} else {
				mountedUSB = false
			}
		}
		if mountedISO {
			if err := runQuiet(cleanupCtx, "umount", "--", isoMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup ISO mount %s: %w", isoMount, err))
			} else {
				mountedISO = false
			}
		}
		if !mountedUSB && !mountedISO {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary work directory: %w", err))
			}
		}
	}()
	for _, directory := range []string{isoMount, usbMount, splitDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}

	send(emit, Event{Stage: "inspect", Message: "Opening and checking the Windows ISO…"})
	if err := run(ctx, emit, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, isoMount); err != nil {
		return fmt.Errorf("mount ISO: %w", err)
	}
	mountedISO = true

	plan, err := inspectMountedISO(isoMount)
	if err != nil {
		return err
	}
	if opts.RequireARM64 && !plan.HasARM64 {
		return errors.New("this ISO contains only x86/x86-64 Windows boot files and will not boot this ARM64 computer; choose an official Windows ARM64 ISO")
	}
	scheme, targetSystem, err := resolveWindowsLayout(plan, opts.PartitionScheme, opts.TargetSystem)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(opts.PartitionScheme), "auto") || strings.TrimSpace(opts.PartitionScheme) == "" ||
		strings.EqualFold(strings.TrimSpace(opts.TargetSystem), "auto") || strings.TrimSpace(opts.TargetSystem) == "" {
		send(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Automatic Windows layout resolved to %s/%s from the selected image capabilities.", strings.ToUpper(scheme), strings.ToUpper(targetSystem))})
	}
	if targetSystem == "bios" {
		if !plan.HasX64 && !plan.HasX86 {
			return errors.New("legacy BIOS/CSM Windows media requires an x86 or x86-64 ISO; Windows ARM64 boots through UEFI only")
		}
		if !plan.HasBootmgr {
			return errors.New("this Windows ISO has no root bootmgr file and cannot be made legacy-BIOS bootable")
		}
	}
	if strings.TrimSpace(opts.DBXPath) != "" {
		dbxPath, err := filepath.Abs(opts.DBXPath)
		if err != nil {
			return fmt.Errorf("resolve Secure Boot DBX file: %w", err)
		}
		if err := safety.EnsurePathNotOnTarget(dbxPath, devicePath); err != nil {
			return fmt.Errorf("secure boot DBX file is unsafe: %w", err)
		}
		database, err := secureboot.ParseFile(dbxPath)
		if err != nil {
			return fmt.Errorf("read Secure Boot DBX: %w", err)
		}
		send(emit, Event{Stage: "secure_boot", Message: "Checking Windows EFI boot files against the Secure Boot revocation database…"})
		results, err := secureboot.ScanEFIDirectory(isoMount, database, 512)
		if err != nil {
			return fmt.Errorf("scan Windows EFI boot files: %w", err)
		}
		checked := 0
		for _, result := range results {
			if result.Error != "" {
				return fmt.Errorf("check EFI boot file %s: %s", result.Path, result.Error)
			}
			checked++
			if result.DirectHashRevoked || result.X509CertificateRevoked {
				return fmt.Errorf("windows boot file %s is revoked by the selected Secure Boot DBX; no USB data was changed", result.Path)
			}
		}
		send(emit, Event{Stage: "secure_boot", Message: fmt.Sprintf("Checked %d EFI boot files; no direct hash or embedded-certificate revocation was found.", checked)})
	}
	fatCompatibilityErr := validateFATCompatibility(isoMount, plan)
	filesystem, err := resolveFilesystem(opts.Filesystem, fatCompatibilityErr)
	if err != nil {
		return err
	}
	plan.Filesystem = filesystem
	plan.NeedsSplit = filesystem == "fat32" && plan.InstallSize > fat32MaxFileSize
	if filesystem == "ntfs" && fatCompatibilityErr != nil && strings.EqualFold(strings.TrimSpace(opts.Filesystem), "auto") {
		send(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Automatic filesystem selection chose NTFS because FAT32 is incompatible with this ISO: %v", fatCompatibilityErr)})
	}
	if strings.TrimSpace(opts.DriverFolder) != "" {
		driverRoot, err := filepath.Abs(opts.DriverFolder)
		if err != nil {
			return fmt.Errorf("resolve Windows driver folder: %w", err)
		}
		if err := safety.EnsurePathNotOnTarget(driverRoot, devicePath); err != nil {
			return fmt.Errorf("windows driver folder is unsafe: %w", err)
		}
		plan.DriverBytes, err = inspectDriverFolder(driverRoot, filesystem)
		if err != nil {
			return err
		}
		plan.DriverFolder = driverRoot
	}
	customizations := opts.Customizations
	customizations.LoadDrivers = plan.DriverFolder != ""
	plan.AnswerFile, err = preparePlanAnswerFile(ctx, plan, customizations, PrepareCustomizations)
	if err != nil {
		return fmt.Errorf("prepare Windows setup options: %w", err)
	}
	if err := finalizePlan(&plan); err != nil {
		return fmt.Errorf("calculate Windows media capacity: %w", err)
	}

	var ntfsFormatter string
	var uefiNTFSImage string
	var uefiNTFSImageSize uint64
	switch filesystem {
	case "fat32":
		for _, name := range []string{"mkfs.vfat", "fsck.vfat"} {
			if _, err := exec.LookPath(name); err != nil {
				return fmt.Errorf("required program %q is not installed", name)
			}
		}
	case "ntfs":
		ntfsFormatter, err = ntfsFormatterExecutable()
		if err != nil {
			return err
		}
		if _, err := exec.LookPath("ntfsfix"); err != nil {
			return errors.New("NTFS support requires ntfsfix from the 'ntfs-3g' package")
		}
		if targetSystem == "uefi" {
			uefiNTFSImage, uefiNTFSImageSize, err = uefiNTFSImageFile()
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported filesystem %q", filesystem)
	}

	label, err := normalizeVolumeLabel(opts.VolumeLabel, filesystem)
	if err != nil {
		return err
	}
	if opts.TargetSize == 0 {
		opts.TargetSize, err = blockDeviceSize(ctx, devicePath)
		if err != nil {
			return err
		}
	}
	sectorSize, err := logicalSectorSize(ctx, devicePath)
	if err != nil {
		return err
	}
	if err := validateClusterBytes(opts.ClusterSize); err != nil {
		return err
	}
	clusterSectors := uint64(0)
	if filesystem == "fat32" {
		clusterSectors, err = clusterSectorCount(opts.ClusterSize, sectorSize)
		if err != nil {
			return err
		}
	}
	if scheme == "mbr" {
		if filesystem == "ntfs" && targetSystem == "uefi" {
			if _, err := mbrUEFINTFSLayoutForSize(opts.TargetSize, sectorSize, uefiNTFSImageSize); err != nil {
				return err
			}
		} else if _, err := mbrLayoutForSize(opts.TargetSize, sectorSize); err != nil {
			return err
		}
	}
	if opts.TargetSize < plan.RequiredBytes {
		return fmt.Errorf("the USB drive is too small: need at least %s, but the drive is %s", humanBytes(plan.RequiredBytes), humanBytes(opts.TargetSize))
	}
	if len(plan.ExistingSplitFiles) > 0 && filesystem == "fat32" {
		if _, err := validateSplitParts(plan.ExistingSplitFiles); err != nil {
			return fmt.Errorf("validate ISO split Windows image: %w", err)
		}
	}

	if plan.NeedsSplit {
		if _, err := wimlibExecutable(); err != nil {
			return err
		}
		temporaryMargin := plan.InstallSize / 10
		if temporaryMargin < minimumFreeMargin {
			temporaryMargin = minimumFreeMargin
		}
		requiredTemporarySpace, err := checkedAdd("temporary split-image space", plan.InstallSize, temporaryMargin)
		if err != nil {
			return err
		}
		if err := ensureAvailableSpace(splitDir, requiredTemporarySpace); err != nil {
			return err
		}
		send(emit, Event{Stage: "split", Message: "Preparing the large Windows installation image before erasing the USB…"})
		plan.SplitFiles, plan.SplitBytes, err = prepareSplitImage(ctx, plan.InstallPath, splitDir, emit)
		if err != nil {
			return err
		}
		if err := finalizePlan(&plan); err != nil {
			return fmt.Errorf("calculate split Windows media capacity: %w", err)
		}
		if opts.TargetSize < plan.RequiredBytes {
			return fmt.Errorf("the USB drive is too small after preparing the Windows image: need at least %s, but the drive is %s", humanBytes(plan.RequiredBytes), humanBytes(opts.TargetSize))
		}
	}
	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return fmt.Errorf("confirm held Windows ISO before erasing the USB: %w", err)
		}
	} else {
		preDestructiveDigest, err := hashPinnedISO("verify_source", "Rechecking the Windows ISO before erasing the USB (conservative pass 2 of 3)…")
		if err != nil {
			return fmt.Errorf("recheck selected Windows ISO: %w", err)
		}
		if !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
			return errors.New("the selected Windows ISO changed while it was being prepared; nothing was erased")
		}
	}
	send(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Windows %s installation media detected; %s/%s selected; approximately %s will be written.", plan.Architecture, strings.ToUpper(targetSystem), strings.ToUpper(filesystem), humanBytes(plan.CopyBytes))})

	checkTarget := func() error {
		if sourceLease != nil {
			if err := sourceLease.Check(); err != nil {
				return err
			}
		}
		if err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
			return err
		}
		return safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize)
	}
	runOnTarget := func(name string, args ...string) error {
		if err := checkTarget(); err != nil {
			return err
		}
		return run(ctx, emit, name, args...)
	}

	if err := checkTarget(); err != nil {
		return err
	}
	if opts.BeforeDestructive != nil {
		if err := opts.BeforeDestructive(isoFile); err != nil {
			return fmt.Errorf("target safety check: %w", err)
		}
	}
	targetChanged = true
	send(emit, Event{Stage: "partition", Message: fmt.Sprintf("Creating a %s partition table…", strings.ToUpper(scheme))})
	if err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {
		return err
	}
	if err := checkTarget(); err != nil {
		return err
	}
	var layout diskLayout
	switch {
	case scheme == "gpt" && filesystem == "fat32":
		data, writeErr := writeSinglePartitionGPT(lock, opts.TargetSize, sectorSize, label)
		layout, err = diskLayout{Data: data}, writeErr
	case scheme == "mbr" && filesystem == "fat32":
		data, writeErr := writeSinglePartitionMBR(lock, opts.TargetSize, sectorSize)
		layout, err = diskLayout{Data: data}, writeErr
	case scheme == "gpt" && filesystem == "ntfs":
		layout, err = writeUEFINTFSGPT(lock, opts.TargetSize, sectorSize, label, uefiNTFSImageSize)
	case scheme == "mbr" && filesystem == "ntfs" && targetSystem == "uefi":
		layout, err = writeUEFINTFSMBR(lock, opts.TargetSize, sectorSize, uefiNTFSImageSize)
	case scheme == "mbr" && filesystem == "ntfs" && targetSystem == "bios":
		data, writeErr := writeSinglePartitionMBRType(lock, opts.TargetSize, sectorSize, 0x07)
		layout, err = diskLayout{Data: data}, writeErr
	default:
		err = fmt.Errorf("unsupported layout %s/%s", scheme, filesystem)
	}
	if err != nil {
		return fmt.Errorf("create %s partition table: %w", strings.ToUpper(scheme), err)
	}
	if layout.Boot != nil {
		if err := writeUEFINTFSPartitionImage(lock, uefiNTFSImage, *layout.Boot); err != nil {
			return err
		}
	}
	if err := checkTarget(); err != nil {
		return err
	}
	if err := rereadPartitionTable(ctx, devicePath, emit); err != nil {
		send(emit, Event{Stage: "partition", Message: fmt.Sprintf("Warning: could not force an immediate partition-table reread: %v", err)})
	}
	if err := checkTarget(); err != nil {
		return err
	}

	partition, err := waitForPartition(ctx, devicePath, 1, layout.Data, 30*time.Second)
	if err != nil {
		return err
	}
	var bootPartition string
	if layout.Boot != nil {
		bootPartition, err = waitForPartition(ctx, devicePath, 2, *layout.Boot, 30*time.Second)
		if err != nil {
			return err
		}
		if err := verifyUEFINTFSPartition(bootPartition, uefiNTFSImage); err != nil {
			return err
		}
	}
	if err := unmountDeviceMounts(ctx, partition); err != nil {
		return err
	}
	if bootPartition != "" {
		if err := unmountDeviceMounts(ctx, bootPartition); err != nil {
			return err
		}
	}
	if opts.FullFormat || opts.BadBlockCheck {
		if err := checkTarget(); err != nil {
			return err
		}
		if err := zeroPartition(ctx, partition, layout.Data.PartitionSizeBytes, emit); err != nil {
			return err
		}
		if err := checkTarget(); err != nil {
			return err
		}
	}
	if opts.BadBlockCheck {
		if err := run(ctx, emit, "blockdev", "--flushbufs", partition); err != nil {
			return fmt.Errorf("flush partition before bad-block verification: %w", err)
		}
		if err := verifyZeroPartition(ctx, partition, layout.Data.PartitionSizeBytes, emit); err != nil {
			return err
		}
		if err := checkTarget(); err != nil {
			return err
		}
	}

	switch filesystem {
	case "fat32":
		send(emit, Event{Stage: "format", Message: fmt.Sprintf("Formatting the USB as FAT32 (%s)…", label)})
		mkfsArgs := []string{"-F", "32", "-n", label}
		if clusterSectors != 0 {
			mkfsArgs = append(mkfsArgs, "-s", strconv.FormatUint(clusterSectors, 10))
		}
		mkfsArgs = append(mkfsArgs, partition)
		if err := run(ctx, emit, "mkfs.vfat", mkfsArgs...); err != nil {
			return err
		}
	case "ntfs":
		send(emit, Event{Stage: "format", Message: fmt.Sprintf("Formatting the main USB partition as NTFS (%s)…", label)})
		mkfsArgs := []string{"-F", "-Q", "-L", label}
		if opts.ClusterSize != 0 {
			mkfsArgs = append(mkfsArgs, "-c", strconv.FormatUint(opts.ClusterSize, 10))
		}
		mkfsArgs = append(mkfsArgs, partition)
		if err := run(ctx, emit, ntfsFormatter, mkfsArgs...); err != nil {
			return err
		}
	}
	if targetSystem == "bios" {
		if err := installLegacyBIOSBoot(lock, partition, filesystem, layout.Data, sectorSize); err != nil {
			return fmt.Errorf("install legacy BIOS boot code: %w", err)
		}
		send(emit, Event{Stage: "boot", Message: "Installed Windows legacy BIOS/CSM MBR and partition boot code."})
	}
	if err := unmountDeviceMounts(ctx, partition); err != nil {
		return err
	}
	if err := run(ctx, emit, "mount", "-o", "rw,nosuid,nodev,noexec", "--", partition, usbMount); err != nil {
		return err
	}
	mountedUSB = true

	send(emit, Event{Stage: "copy", Message: "Copying Windows setup files…", Total: plan.CopyBytes})
	var copied uint64
	report := func(delta uint64) {
		copied += delta
		send(emit, Event{Stage: "copy", Message: "Copying Windows setup files…", Done: copied, Total: plan.CopyBytes})
	}
	answerToExclude := ""
	if len(plan.AnswerFile) > 0 {
		answerToExclude = plan.ExistingAnswerPath
	}
	if err := withExclusiveMount(ctx, partition, usbMount, func(copyCtx context.Context) error {
		if err := copyTree(copyCtx, isoMount, usbMount, plan.InstallPath, answerToExclude, report); err != nil {
			return err
		}
		if plan.InstallPath != "" {
			sourcesDir := filepath.Join(usbMount, "sources")
			if err := os.MkdirAll(sourcesDir, 0o755); err != nil {
				return err
			}
			if !plan.NeedsSplit {
				dest := filepath.Join(sourcesDir, strings.ToLower(filepath.Base(plan.InstallPath)))
				if err := copyFile(copyCtx, plan.InstallPath, dest, report); err != nil {
					return fmt.Errorf("copy Windows installation image: %w", err)
				}
			} else {
				for _, source := range plan.SplitFiles {
					destination := filepath.Join(sourcesDir, filepath.Base(source))
					if err := copyFile(copyCtx, source, destination, report); err != nil {
						return fmt.Errorf("copy split Windows image %s: %w", filepath.Base(source), err)
					}
				}
			}
		}
		if len(plan.AnswerFile) > 0 {
			answerPath := filepath.Join(usbMount, "autounattend.xml")
			if err := os.WriteFile(answerPath, plan.AnswerFile, 0o644); err != nil {
				return fmt.Errorf("write Windows setup options: %w", err)
			}
			report(uint64(len(plan.AnswerFile)))
		}
		if plan.DriverFolder != "" {
			destination := filepath.Join(usbMount, "drivers")
			if err := os.MkdirAll(destination, 0o755); err != nil {
				return err
			}
			if err := copyTreeWithOptions(copyCtx, plan.DriverFolder, destination, "", "", true, report); err != nil {
				return fmt.Errorf("copy Windows drivers: %w", err)
			}
			if err := os.WriteFile(filepath.Join(usbMount, rufusDriverMarkerName), rufusDriverMarker, 0o644); err != nil {
				return fmt.Errorf("write Windows driver marker: %w", err)
			}
			report(uint64(len(rufusDriverMarker)))
		}
		return nil
	}); err != nil {
		return err
	}

	send(emit, Event{Stage: "sync", Message: "Flushing pending USB writes safely…"})
	if err := run(ctx, emit, "sync", "-f", usbMount); err != nil {
		return err
	}
	if err := run(ctx, emit, "umount", "--", usbMount); err != nil {
		return err
	}
	mountedUSB = false
	if err := checkTarget(); err != nil {
		return err
	}
	if err := run(ctx, emit, "blockdev", "--flushbufs", partition); err != nil {
		return fmt.Errorf("flush USB buffers: %w", err)
	}

	if opts.Verify {
		if err := checkTarget(); err != nil {
			return err
		}
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…"})
		if err := run(ctx, emit, "mount", "-o", "ro,nosuid,nodev,noexec", "--", partition, usbMount); err != nil {
			return err
		}
		mountedUSB = true
		if err := withExclusiveMount(ctx, partition, usbMount, func(verifyCtx context.Context) error {
			if err := verifyTree(verifyCtx, isoMount, usbMount, plan, emit); err != nil {
				return err
			}
			if plan.DriverFolder != "" {
				return verifyDirectory(verifyCtx, plan.DriverFolder, filepath.Join(usbMount, "drivers"), emit, &plan)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := run(ctx, emit, "umount", "--", usbMount); err != nil {
			return err
		}
		mountedUSB = false
	}

	if err := checkTarget(); err != nil {
		return err
	}
	switch filesystem {
	case "fat32":
		send(emit, Event{Stage: "check", Message: "Checking the FAT32 filesystem…"})
		if err := run(ctx, emit, "fsck.vfat", "-n", partition); err != nil {
			return fmt.Errorf("FAT32 filesystem check failed: %w", err)
		}
	case "ntfs":
		send(emit, Event{Stage: "check", Message: "Checking the NTFS filesystem…"})
		if err := run(ctx, emit, "ntfsfix", "-n", partition); err != nil {
			return fmt.Errorf("NTFS filesystem check failed: %w", err)
		}
	}
	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return fmt.Errorf("confirm held Windows ISO after copying: %w", err)
		}
	} else {
		postCopyDigest, err := hashPinnedISO("verify_source", "Checking that the source ISO stayed unchanged (conservative pass 3 of 3)…")
		if err != nil {
			return fmt.Errorf("recheck Windows ISO after copying: %w", err)
		}
		if !bytes.Equal(sourceDigest[:], postCopyDigest[:]) {
			return errors.New("the selected Windows ISO changed while files were being copied; the USB is incomplete and must be recreated")
		}
	}
	if err := run(ctx, emit, "umount", "--", isoMount); err != nil {
		return err
	}
	mountedISO = false
	return nil
}

func inspectMountedISO(root string) (mediaPlan, error) {
	if _, ok := findRelativeCaseInsensitive(root, "sources/boot.wim"); !ok {
		return mediaPlan{}, errors.New("this is not a supported Windows installation ISO: sources/boot.wim was not found")
	}

	_, arm64 := findRelativeCaseInsensitive(root, "efi/boot/bootaa64.efi")
	_, x64 := findRelativeCaseInsensitive(root, "efi/boot/bootx64.efi")
	_, x86 := findRelativeCaseInsensitive(root, "efi/boot/bootia32.efi")
	_, bootmgr := findRelativeCaseInsensitive(root, "bootmgr")
	architecture := "UEFI"
	switch {
	case arm64 && x64:
		architecture = "ARM64/x86-64 UEFI"
	case arm64:
		architecture = "ARM64 UEFI"
	case x64:
		architecture = "x86-64 UEFI"
	case x86:
		architecture = "x86 UEFI"
	default:
		return mediaPlan{}, errors.New("the ISO has no standard ARM64 or x86-64 UEFI boot file")
	}

	installWIM, hasWIM := findRelativeCaseInsensitive(root, "sources/install.wim")
	installESD, hasESD := findRelativeCaseInsensitive(root, "sources/install.esd")
	existingSplitFiles, err := findExistingSplitFiles(root)
	if err != nil {
		return mediaPlan{}, err
	}
	payloadKinds := 0
	if hasWIM {
		payloadKinds++
	}
	if hasESD {
		payloadKinds++
	}
	if len(existingSplitFiles) > 0 {
		payloadKinds++
	}
	if payloadKinds == 0 {
		return mediaPlan{}, errors.New("this Windows ISO has no sources/install.wim, sources/install.esd, or split install.swm payload")
	}
	if payloadKinds > 1 {
		return mediaPlan{}, errors.New("this Windows ISO contains conflicting installation payloads (WIM, ESD, or SWM)")
	}
	installPath := installWIM
	if hasESD {
		installPath = installESD
	}
	hasInstall := hasWIM || hasESD
	plan := mediaPlan{
		InstallPath:        installPath,
		ExistingSplitFiles: existingSplitFiles,
		Architecture:       architecture,
		HasARM64:           arm64,
		HasX64:             x64,
		HasX86:             x86,
		HasBootmgr:         bootmgr,
	}
	if answerPath, ok := findRelativeCaseInsensitive(root, "autounattend.xml"); ok {
		plan.ExistingAnswerPath = answerPath
		if info, statErr := os.Stat(answerPath); statErr == nil {
			plan.ExistingAnswerSize = uint64(info.Size())
		}
	}
	if hasInstall {
		rel, err := filepath.Rel(root, installPath)
		if err != nil {
			return mediaPlan{}, err
		}
		plan.InstallRelative = filepath.Clean(rel)
		info, err := os.Stat(installPath)
		if err != nil {
			return mediaPlan{}, fmt.Errorf("read Windows installation image: %w", err)
		}
		plan.InstallSize = uint64(info.Size())
	}

	entryCount := 0
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxWindowsMediaEntries, "Windows ISO"); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsupported symbolic link in ISO: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in ISO: %s", path)
		}
		if !samePath(path, plan.InstallPath) {
			plan.OtherBytes, err = checkedAdd("Windows ISO file total", plan.OtherBytes, uint64(info.Size()))
			if err != nil {
				return err
			}
		}
		return nil
	})
	if walkErr != nil {
		return mediaPlan{}, walkErr
	}
	// Default sizing keeps the inspector useful in tests and callers that only
	// need a conservative plan. Create resolves the requested filesystem and
	// recalculates these values before any destructive operation.
	plan.Filesystem = "fat32"
	plan.NeedsSplit = plan.InstallSize > fat32MaxFileSize
	if err := finalizePlan(&plan); err != nil {
		return mediaPlan{}, err
	}
	return plan, nil
}

// validateFATCompatibility performs the checks that matter only when the main
// data partition is FAT32. The oversized install image is intentionally
// excluded because it can be split into Windows-supported SWM parts.
func validateFATCompatibility(root string, plan mediaPlan) error {
	seenFATPaths := make(map[string]string)
	entryCount := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxWindowsMediaEntries, "Windows ISO"); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative != "." {
			if err := validateFATRelativePath(relative); err != nil {
				return err
			}
			key := strings.ToLower(filepath.ToSlash(relative))
			if previous, exists := seenFATPaths[key]; exists {
				return fmt.Errorf("the ISO contains names that collide on FAT32: %s and %s", filepath.ToSlash(previous), filepath.ToSlash(relative))
			}
			seenFATPaths[key] = relative
		}
		if entry.IsDir() || samePath(path, plan.InstallPath) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if uint64(info.Size()) > fat32MaxFileSize {
			return fmt.Errorf("the ISO contains another file too large for FAT32: %s (%s); choose NTFS", filepath.ToSlash(relative), humanBytes(uint64(info.Size())))
		}
		return nil
	})
}

func inspectDriverFolder(root string, filesystem string) (uint64, error) {
	if strings.TrimSpace(root) == "" {
		return 0, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return 0, fmt.Errorf("open Windows driver folder: %w", err)
	}
	if !info.IsDir() {
		return 0, errors.New("the Windows driver path is not a directory")
	}
	var total uint64
	entryCount := 0
	hasINF := false
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxDriverFolderEntries, "Windows driver folder"); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("driver folder contains a symbolic link: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative != "." && filesystem == "fat32" {
			if err := validateFATRelativePath(filepath.Join("drivers", relative)); err != nil {
				return err
			}
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("driver folder contains a non-regular file: %s", path)
		}
		if filesystem == "fat32" && uint64(fileInfo.Size()) > fat32MaxFileSize {
			return fmt.Errorf("driver file is too large for FAT32: %s", path)
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".inf") {
			hasINF = true
		}
		total, err = checkedAdd("Windows driver folder total", total, uint64(fileInfo.Size()))
		return err
	})
	if err != nil {
		return 0, err
	}
	if !hasINF {
		return 0, errors.New("the selected driver folder contains no .inf driver files")
	}
	return total, nil
}

func finalizePlan(plan *mediaPlan) error {
	if plan == nil {
		return errors.New("windows media plan is nil")
	}
	installOutput := plan.InstallSize
	if plan.NeedsSplit && plan.SplitBytes > 0 {
		installOutput = plan.SplitBytes
	}
	otherBytes := plan.OtherBytes
	if len(plan.AnswerFile) > 0 {
		if plan.ExistingAnswerSize > otherBytes {
			return errors.New("existing Windows answer file size exceeds the inspected media total")
		}
		otherBytes -= plan.ExistingAnswerSize
		var err error
		otherBytes, err = checkedAdd("Windows answer-file replacement total", otherBytes, uint64(len(plan.AnswerFile)))
		if err != nil {
			return err
		}
	}
	copyBytes, err := checkedAdd("Windows media copy size", otherBytes, installOutput, plan.DriverBytes)
	if err != nil {
		return err
	}
	if plan.DriverFolder != "" {
		copyBytes, err = checkedAdd("Windows media copy size", copyBytes, uint64(len(rufusDriverMarker)))
		if err != nil {
			return err
		}
	}
	plan.CopyBytes = copyBytes
	marginDivisor := uint64(10)
	if plan.Filesystem == "ntfs" {
		marginDivisor = 20
	}
	margin := plan.CopyBytes / marginDivisor
	if margin < minimumFreeMargin {
		margin = minimumFreeMargin
	}
	reserve := uint64(2 * 1024 * 1024)
	if plan.Filesystem == "ntfs" {
		reserve += oneMiB
	}
	plan.RequiredBytes, err = checkedAdd("required Windows USB capacity", plan.CopyBytes, margin, reserve)
	return err
}

func prepareSplitImage(ctx context.Context, sourcePath, splitDir string, emit EventFunc) ([]string, uint64, error) {
	firstPart := filepath.Join(splitDir, "install.swm")
	wimlib, err := wimlibExecutable()
	if err != nil {
		return nil, 0, err
	}
	if err := run(ctx, emit, wimlib, "split", sourcePath, firstPart, splitPartMiB); err != nil {
		return nil, 0, fmt.Errorf("split Windows installation image: %w", err)
	}
	parts, err := filepath.Glob(filepath.Join(splitDir, "install*.swm"))
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return nil, 0, errors.New("wimlib completed without producing split WIM parts")
	}
	total, err := validateSplitParts(parts)
	if err != nil {
		return nil, 0, err
	}
	return parts, total, nil
}

func findExistingSplitFiles(root string) ([]string, error) {
	sources, ok := findRelativeCaseInsensitive(root, "sources")
	if !ok {
		return nil, nil
	}
	entries, err := os.ReadDir(sources)
	if err != nil {
		return nil, err
	}
	parts := make(map[int]string)
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.IsDir() || !strings.HasPrefix(name, "install") || !strings.HasSuffix(name, ".swm") {
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(name, "install"), ".swm")
		index := 1
		if middle != "" {
			if _, err := fmt.Sscan(middle, &index); err != nil || index < 2 || fmt.Sprintf("%d", index) != middle {
				return nil, fmt.Errorf("invalid split Windows image filename: %s", entry.Name())
			}
		}
		if previous, exists := parts[index]; exists {
			return nil, fmt.Errorf("duplicate split Windows image parts: %s and %s", previous, entry.Name())
		}
		parts[index] = filepath.Join(sources, entry.Name())
	}
	if len(parts) == 0 {
		return nil, nil
	}
	if _, ok := parts[1]; !ok {
		return nil, errors.New("the ISO contains numbered install*.swm files but is missing sources/install.swm")
	}
	result := make([]string, 0, len(parts))
	for index := 1; index <= len(parts); index++ {
		part, ok := parts[index]
		if !ok {
			return nil, fmt.Errorf("the ISO split Windows image is missing part %d", index)
		}
		result = append(result, part)
	}
	return result, nil
}

func validateFATRelativePath(relative string) error {
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if !utf8.ValidString(component) {
			return fmt.Errorf("the ISO contains a filename with invalid UTF-8 encoding: %s", filepath.ToSlash(relative))
		}
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("the ISO contains an invalid FAT32 path: %s", filepath.ToSlash(relative))
		}
		if len(utf16.Encode([]rune(component))) > 255 || strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") {
			return fmt.Errorf("the ISO contains a filename that cannot be represented safely on FAT32: %s", filepath.ToSlash(relative))
		}
		for _, char := range component {
			if char < 0x20 || strings.ContainsRune(`<>:"\\|?*`, char) {
				return fmt.Errorf("the ISO contains a filename that cannot be represented safely on FAT32: %s", filepath.ToSlash(relative))
			}
		}
		base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		reserved := base == "CON" || base == "PRN" || base == "AUX" || base == "NUL"
		if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			reserved = true
		}
		if reserved {
			return fmt.Errorf("the ISO contains a Windows-reserved filename: %s", filepath.ToSlash(relative))
		}
	}
	return nil
}

func createWorkDir() (string, error) {
	base := os.TempDir()
	if info, err := os.Stat("/var/tmp"); err == nil && info.IsDir() {
		base = "/var/tmp"
	}
	workDir, err := os.MkdirTemp(base, "rufusarm64-")
	if err != nil {
		return "", fmt.Errorf("create temporary work directory: %w", err)
	}
	return workDir, nil
}

func ensureAvailableSpace(path string, required uint64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("check temporary free space: %w", err)
	}
	available, err := checkedMultiply("temporary filesystem free space", uint64(stat.Bavail), uint64(stat.Bsize))
	if err != nil {
		return err
	}
	if available < required {
		return fmt.Errorf("not enough temporary disk space to prepare the Windows image safely: need %s, available %s", humanBytes(required), humanBytes(available))
	}
	return nil
}

func validateSplitParts(parts []string) (uint64, error) {
	if len(parts) == 0 {
		return 0, errors.New("no split WIM parts were produced")
	}
	var total uint64
	for _, part := range parts {
		info, err := os.Stat(part)
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 {
			return 0, fmt.Errorf("invalid split WIM part: %s", part)
		}
		size := uint64(info.Size())
		if size > fat32MaxFileSize {
			return 0, fmt.Errorf("%s is %s and cannot fit on FAT32; this ISO contains a resource that wimlib cannot split below the FAT32 file limit", filepath.Base(part), humanBytes(size))
		}
		total, err = checkedAdd("split Windows image total", total, size)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func copyTree(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, progress func(uint64)) error {
	return copyTreeWithOptions(ctx, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath, false, progress)
}

// copyTreeWithOptions copies a directory tree. When untrustedSource is true
// every source file is opened through openWithinRoot, which refuses symbolic
// links in every path component and refuses escapes from sourceRoot. The
// privileged helper copies the user-selected Windows driver folder as root, so
// a symlink swapped in between validation and copy must not be able to place
// root-readable files onto the world-readable USB filesystem.
func copyTreeWithOptions(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, untrustedSource bool, progress func(uint64)) error {
	var rootHandle *os.File
	if untrustedSource {
		handle, err := openDirectoryNoFollow(sourceRoot)
		if err != nil {
			return fmt.Errorf("open source folder: %w", err)
		}
		defer handle.Close()
		rootHandle = handle
	}
	return filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if samePath(path, excludedPath) || samePath(path, excludedAnswerPath) {
			return nil
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		destination := filepath.Join(destinationRoot, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported file in source tree: %s", path)
		}
		var source *os.File
		if untrustedSource {
			source, err = openWithinRoot(rootHandle, relative)
		} else {
			source, err = os.Open(path)
		}
		if err != nil {
			return fmt.Errorf("copy %s: %w", filepath.ToSlash(relative), err)
		}
		copyErr := copyFromOpenFile(ctx, source, destination, progress)
		closeErr := source.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			return fmt.Errorf("copy %s: %w", filepath.ToSlash(relative), copyErr)
		}
		_ = os.Chtimes(destination, info.ModTime(), info.ModTime())
		return nil
	})
}

func verifyTree(ctx context.Context, sourceRoot, destinationRoot string, plan mediaPlan, emit EventFunc) error {
	total := plan.CopyBytes - plan.DriverBytes
	var done uint64
	err := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || samePath(path, plan.InstallPath) || (len(plan.AnswerFile) > 0 && samePath(path, plan.ExistingAnswerPath)) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(destinationRoot, relative)
		n, err := compareFiles(path, destination)
		if err != nil {
			return fmt.Errorf("verify %s: %w", filepath.ToSlash(relative), err)
		}
		done += n
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…", Done: done, Total: total})
		return nil
	})
	if err != nil {
		return err
	}

	if plan.InstallPath != "" && !plan.NeedsSplit {
		destination := filepath.Join(destinationRoot, "sources", strings.ToLower(filepath.Base(plan.InstallPath)))
		n, err := compareFiles(plan.InstallPath, destination)
		if err != nil {
			return fmt.Errorf("verify Windows installation image: %w", err)
		}
		done += n
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…", Done: done, Total: total})
	}
	for _, source := range plan.SplitFiles {
		destination := filepath.Join(destinationRoot, "sources", filepath.Base(source))
		n, err := compareFiles(source, destination)
		if err != nil {
			return fmt.Errorf("verify split Windows image %s: %w", filepath.Base(source), err)
		}
		done += n
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…", Done: done, Total: total})
	}
	if len(plan.AnswerFile) > 0 {
		destination := filepath.Join(destinationRoot, "autounattend.xml")
		data, err := os.ReadFile(destination)
		if err != nil {
			return fmt.Errorf("verify Windows setup options: %w", err)
		}
		if !bytes.Equal(data, plan.AnswerFile) {
			return errors.New("verify Windows setup options: content mismatch")
		}
		done += uint64(len(data))
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…", Done: done, Total: total})
	}
	if plan.DriverFolder != "" {
		markerPath := filepath.Join(destinationRoot, rufusDriverMarkerName)
		data, err := os.ReadFile(markerPath)
		if err != nil {
			return fmt.Errorf("verify Windows driver marker: %w", err)
		}
		if !bytes.Equal(data, rufusDriverMarker) {
			return errors.New("verify Windows driver marker: content mismatch")
		}
		done += uint64(len(data))
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…", Done: done, Total: total})
	}
	return nil
}

func compareFiles(leftPath, rightPath string) (uint64, error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return 0, err
	}
	defer left.Close()
	return compareOpenFileToPath(left, rightPath)
}

func compareOpenFileToPath(left *os.File, rightPath string) (uint64, error) {
	leftInfo, err := left.Stat()
	if err != nil {
		return 0, err
	}
	if !leftInfo.Mode().IsRegular() {
		return 0, errors.New("source is not a regular file")
	}
	rightInfo, err := os.Stat(rightPath)
	if err != nil {
		return 0, err
	}
	if !rightInfo.Mode().IsRegular() {
		return 0, errors.New("destination is not a regular file")
	}
	if leftInfo.Size() != rightInfo.Size() {
		return 0, fmt.Errorf("size mismatch: source=%d destination=%d", leftInfo.Size(), rightInfo.Size())
	}
	leftHash, err := openFileSHA256(left)
	if err != nil {
		return 0, err
	}
	rightHash, err := fileSHA256(rightPath)
	if err != nil {
		return 0, err
	}
	if leftHash != rightHash {
		return 0, errors.New("SHA-256 mismatch")
	}
	return uint64(leftInfo.Size()), nil
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	return openFileSHA256(file)
}

func openFileSHA256(file *os.File) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if file == nil {
		return result, errors.New("file is nil")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, copyBufferSize)); err != nil {
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func wimlibExecutable() (string, error) {
	candidates := make([]string, 0, 3)
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "wimlib-imagex"))
	}
	candidates = append(candidates, bundledWimlibPath)
	for _, candidate := range candidates {
		if executableFile(candidate) {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath("wimlib-imagex"); err == nil {
		return path, nil
	}
	return "", errors.New("this Windows ISO needs WIM support, but wimlib-imagex is unavailable; install Ubuntu's 'wimtools' package or use a RufusArm64 build that includes the bundled WIM engine")
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func ntfsFormatterExecutable() (string, error) {
	for _, name := range []string{"mkfs.ntfs", "mkntfs"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("NTFS support requires mkfs.ntfs (or mkntfs) from the 'ntfs-3g' package")
}

func uefiNTFSImageFile() (string, uint64, error) {
	candidates := make([]string, 0, 5)
	if envPath := strings.TrimSpace(os.Getenv("RUFUSARM64_UEFI_NTFS_IMAGE")); envPath != "" {
		candidates = append(candidates, envPath)
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "uefi-ntfs.img"))
	}
	candidates = append(candidates, bundledUEFINTFSPath, filepath.Join("vendor", "uefi-ntfs", "uefi-ntfs.img"))
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		hash, err := fileSHA256(candidate)
		if err != nil {
			return "", 0, fmt.Errorf("verify UEFI:NTFS image: %w", err)
		}
		if fmt.Sprintf("%x", hash) != uefiNTFSImageSHA256 {
			return "", 0, fmt.Errorf("refusing modified UEFI:NTFS image %s: SHA-256 mismatch", candidate)
		}
		return candidate, uint64(info.Size()), nil
	}
	return "", 0, errors.New("NTFS boot support is unavailable because the verified UEFI:NTFS image is missing")
}

func writeUEFINTFSPartitionImage(target *os.File, imagePath string, layout partitionLayout) error {
	image, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open UEFI:NTFS image: %w", err)
	}
	defer image.Close()
	info, err := image.Stat()
	if err != nil {
		return fmt.Errorf("stat UEFI:NTFS image: %w", err)
	}
	if uint64(info.Size()) != layout.PartitionSizeBytes {
		return fmt.Errorf("UEFI:NTFS image is %d bytes but its partition is %d bytes", info.Size(), layout.PartitionSizeBytes)
	}
	writer := io.NewOffsetWriter(target, int64(layout.PartitionStartBytes))
	written, err := io.CopyBuffer(writer, image, make([]byte, copyBufferSize))
	if err != nil {
		return fmt.Errorf("write UEFI:NTFS partition image: %w", err)
	}
	if uint64(written) != layout.PartitionSizeBytes {
		return fmt.Errorf("short UEFI:NTFS image write: wrote %d of %d bytes", written, layout.PartitionSizeBytes)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("flush UEFI:NTFS partition image: %w", err)
	}

	// Verify the bytes through the already-open whole-disk descriptor before we
	// ask the kernel to re-read the partition table. This catches short, stale,
	// or redirected writes even when the eventual partition node never appears.
	expected, err := fileSHA256(imagePath)
	if err != nil {
		return fmt.Errorf("hash UEFI:NTFS source image: %w", err)
	}
	hash := sha256.New()
	reader := io.NewSectionReader(target, int64(layout.PartitionStartBytes), int64(layout.PartitionSizeBytes))
	if _, err := io.Copy(hash, reader); err != nil {
		return fmt.Errorf("read back UEFI:NTFS partition image: %w", err)
	}
	if !bytes.Equal(expected[:], hash.Sum(nil)) {
		return errors.New("UEFI:NTFS partition image verification failed: SHA-256 mismatch")
	}
	return nil
}

func verifyUEFINTFSPartition(partitionPath, imagePath string) error {
	// Hermetic integration tests use regular files as synthetic partition nodes.
	// The whole-disk write path has already performed an exact section readback,
	// while real operations always reach this function with a block device node.
	if info, err := os.Stat(partitionPath); err == nil && info.Mode().IsRegular() {
		return nil
	}
	expected, err := fileSHA256(imagePath)
	if err != nil {
		return fmt.Errorf("hash UEFI:NTFS source image: %w", err)
	}
	imageInfo, err := os.Stat(imagePath)
	if err != nil {
		return err
	}
	partition, err := os.Open(partitionPath)
	if err != nil {
		return fmt.Errorf("open UEFI:NTFS boot partition: %w", err)
	}
	defer partition.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, partition, imageInfo.Size()); err != nil {
		return fmt.Errorf("read back UEFI:NTFS boot partition: %w", err)
	}
	if !bytes.Equal(expected[:], hash.Sum(nil)) {
		return errors.New("UEFI:NTFS boot partition verification failed: SHA-256 mismatch")
	}
	return nil
}

func verifyDirectory(ctx context.Context, sourceRoot, destinationRoot string, emit EventFunc, plan *mediaPlan) error {
	rootHandle, err := openDirectoryNoFollow(sourceRoot)
	if err != nil {
		return fmt.Errorf("open driver folder for verification: %w", err)
	}
	defer rootHandle.Close()

	var done uint64
	err = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("driver folder changed to a symbolic link during verification: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		source, err := openWithinRoot(rootHandle, relative)
		if err != nil {
			return fmt.Errorf("verify driver %s: %w", filepath.ToSlash(relative), err)
		}
		n, compareErr := compareOpenFileToPath(source, filepath.Join(destinationRoot, relative))
		closeErr := source.Close()
		if compareErr == nil {
			compareErr = closeErr
		}
		if compareErr != nil {
			return fmt.Errorf("verify driver %s: %w", filepath.ToSlash(relative), compareErr)
		}
		done += n
		send(emit, Event{Stage: "verify_drivers", Message: "Verifying copied Windows drivers from the USB…", Done: done, Total: plan.DriverBytes})
		return nil
	})
	return err
}

func normalizeVolumeLabel(value, filesystem string) (string, error) {
	label := strings.ToUpper(strings.TrimSpace(value))
	if label == "" {
		label = "RUFUSARM64"
	}
	limit := 11
	if filesystem == "ntfs" {
		limit = 32
	}
	if len(label) > limit {
		return "", fmt.Errorf("%s volume label must contain at most %d ASCII characters", strings.ToUpper(filesystem), limit)
	}
	for _, r := range label {
		if r < 0x20 || r > 0x7e || strings.ContainsRune(`"*/:<>?\|`, r) {
			return "", fmt.Errorf("%s volume label contains an unsupported character", strings.ToUpper(filesystem))
		}
		if filesystem == "fat32" && strings.ContainsRune(`+,.;=[]`, r) {
			return "", errors.New("FAT32 volume label contains an unsupported character")
		}
	}
	return label, nil
}

var wimPercentPattern = regexp.MustCompile(`\(([0-9]{1,3})%\)`)

func relayToolLine(emit EventFunc, command string, args []string, line string) {
	base := filepath.Base(command)
	if base == "wimlib-imagex" {
		matches := wimPercentPattern.FindStringSubmatch(line)
		if len(matches) == 2 {
			percent, _ := strconv.Atoi(matches[1])
			stage := "wim"
			message := "Processing the Windows installation image…"
			if len(args) > 0 && args[0] == "split" {
				stage = "split"
				message = "Preparing the large Windows installation image…"
			} else if len(args) > 0 && args[0] == "verify" {
				stage = "verify_wim"
				message = "Validating the Windows installation image…"
			}
			send(emit, Event{Stage: stage, Message: message, Done: uint64(percent), Total: 100})
			return
		}
		// Keep warnings and final summaries, but discard repetitive progress lines
		// that do not include a percentage.
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "splitting wim:") || strings.HasPrefix(lower, "calculating integrity table") || strings.HasPrefix(lower, "verifying file data:") || strings.HasPrefix(lower, "verifying integrity of") {
			return
		}
	}
	send(emit, Event{Stage: "log", Message: line})
}

func send(emit EventFunc, event Event) {
	if emit != nil {
		emit(event)
	}
}

func run(ctx context.Context, emit EventFunc, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	stdoutResult := make(chan error, 1)
	stderrResult := make(chan error, 1)
	relay := func(reader io.Reader, result chan<- error) {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 16*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
			if line != "" {
				relayToolLine(emit, name, args, line)
			}
		}
		scanErr := scanner.Err()
		if scanErr != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		result <- scanErr
	}
	go relay(stdout, stdoutResult)
	go relay(stderr, stderrResult)
	stdoutErr := <-stdoutResult
	stderrErr := <-stderrResult
	waitErr := cmd.Wait()
	if stdoutErr != nil {
		return fmt.Errorf("read %s output: %w", name, stdoutErr)
	}
	if stderrErr != nil {
		return fmt.Errorf("read %s error output: %w", name, stderrErr)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed: %w", name, waitErr)
	}
	return nil
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func withExclusiveMount(ctx context.Context, devicePath, expectedMount string, work func(context.Context) error) error {
	if err := ensureOnlyDeviceMount(ctx, devicePath, expectedMount); err != nil {
		return err
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	monitorResult := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				monitorResult <- nil
				return
			case <-ticker.C:
				if err := ensureOnlyDeviceMount(workCtx, devicePath, expectedMount); err != nil {
					if workCtx.Err() != nil {
						monitorResult <- nil
					} else {
						monitorResult <- err
						cancel()
					}
					return
				}
			}
		}
	}()
	workErr := work(workCtx)
	cancel()
	monitorErr := <-monitorResult
	if monitorErr != nil {
		monitorErr = fmt.Errorf("unexpected automatic mount detected: %w", monitorErr)
	}
	return errors.Join(workErr, monitorErr)
}

func ensureOnlyDeviceMount(ctx context.Context, devicePath, expectedMount string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, "findmnt", "-rn", "-S", devicePath, "-o", "TARGET")
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
			return fmt.Errorf("%s is no longer mounted at %s", devicePath, expectedMount)
		}
		if checkCtx.Err() != nil {
			return checkCtx.Err()
		}
		return fmt.Errorf("inspect mounts for %s: %w", devicePath, err)
	}
	expected := filepath.Clean(expectedMount)
	foundExpected := false
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		mountpoint := strings.TrimSpace(scanner.Text())
		if mountpoint == "" {
			continue
		}
		if filepath.Clean(mountpoint) != expected {
			return fmt.Errorf("%s was also mounted at %s", devicePath, mountpoint)
		}
		foundExpected = true
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse mount list for %s: %w", devicePath, err)
	}
	if !foundExpected {
		return fmt.Errorf("%s is no longer mounted at %s", devicePath, expectedMount)
	}
	return nil
}

func unmountDeviceMounts(ctx context.Context, devicePath string) error {
	findCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(findCtx, "findmnt", "-rn", "-S", devicePath, "-o", "TARGET")
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
			return nil // findmnt uses status 1 when there are no matches.
		}
		if findCtx.Err() != nil {
			return findCtx.Err()
		}
		return fmt.Errorf("find mounts for %s: %w", devicePath, err)
	}
	var mountpoints []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		mountpoint := strings.TrimSpace(scanner.Text())
		if mountpoint != "" {
			mountpoints = append(mountpoints, mountpoint)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse mounted target paths: %w", err)
	}
	sort.SliceStable(mountpoints, func(i, j int) bool {
		return strings.Count(filepath.Clean(mountpoints[i]), string(filepath.Separator)) > strings.Count(filepath.Clean(mountpoints[j]), string(filepath.Separator))
	})
	for _, mountpoint := range mountpoints {
		if err := runQuiet(ctx, "umount", "--", mountpoint); err != nil {
			return fmt.Errorf("unmount automatically mounted target %s at %s: %w", devicePath, mountpoint, err)
		}
	}
	return nil
}

func rereadPartitionTable(ctx context.Context, devicePath string, emit EventFunc) error {
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lastErr = runQuiet(commandCtx, "blockdev", "--rereadpt", devicePath)
		cancel()
		if lastErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt == 1 {
			send(emit, Event{Stage: "partition", Message: "Waiting for the kernel to refresh this USB partition…"})
		}
		timer := time.NewTimer(time.Duration(attempt) * 250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("refresh the new partition table for %s: %w", devicePath, lastErr)
}

func waitForPartition(ctx context.Context, devicePath string, index int, layout partitionLayout, timeout time.Duration) (string, error) {
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	candidate := partitionPath(devicePath, index)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if partitionMatchesLayout(candidate, layout) {
			return candidate, nil
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		output, err := exec.CommandContext(probeCtx, "lsblk", "-lnpo", "NAME,TYPE", "--", devicePath).Output()
		cancel()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 2 && fields[1] == "part" && partitionMatchesLayout(fields[0], layout) {
					return fields[0], nil
				}
			}
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("parse lsblk partition output: %w", err)
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the new USB partition did not appear at %s; reconnect the USB and try again", candidate)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func partitionMatchesLayout(partitionPath string, layout partitionLayout) bool {
	info, err := os.Stat(partitionPath)
	if err != nil || (info.Mode()&os.ModeDevice == 0 && !info.Mode().IsRegular()) {
		return false
	}
	// Regular files are used only by the hermetic command tests. Real block
	// devices must match the exact GPT geometry through sysfs, which prevents a
	// stale /dev/sdX1 node from an old partition table being formatted.
	if info.Mode().IsRegular() {
		return true
	}
	base := filepath.Base(partitionPath)
	startSectors, err := readSysfsSectors(filepath.Join("/sys/class/block", base, "start"))
	if err != nil {
		return false
	}
	sizeSectors, err := readSysfsSectors(filepath.Join("/sys/class/block", base, "size"))
	if err != nil {
		return false
	}
	return startSectors*512 == layout.PartitionStartBytes && sizeSectors*512 == layout.PartitionSizeBytes
}

func readSysfsSectors(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func firstPartitionPath(devicePath string) string {
	return partitionPath(devicePath, 1)
}

func partitionPath(devicePath string, index int) string {
	base := filepath.Base(devicePath)
	suffix := strconv.Itoa(index)
	if base != "" && base[len(base)-1] >= '0' && base[len(base)-1] <= '9' {
		return devicePath + "p" + suffix
	}
	return devicePath + suffix
}

func findRelativeCaseInsensitive(root, relative string) (string, bool) {
	current := root
	for _, wanted := range strings.Split(filepath.ToSlash(relative), "/") {
		entries, err := os.ReadDir(current)
		if err != nil {
			return "", false
		}
		found := ""
		for _, entry := range entries {
			if strings.EqualFold(entry.Name(), wanted) {
				found = entry.Name()
				break
			}
		}
		if found == "" {
			return "", false
		}
		current = filepath.Join(current, found)
	}
	return current, true
}

func copyFile(ctx context.Context, sourcePath, destinationPath string, progress func(uint64)) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	return copyFromOpenFile(ctx, source, destinationPath, progress)
}

func copyFromOpenFile(ctx context.Context, source *os.File, destinationPath string, progress func(uint64)) (returnErr error) {
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if destination != nil {
			if err := destination.Close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close destination file: %w", err))
			}
		}
	}()
	buffer := make([]byte, copyBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			written, writeErr := writeFull(destination, buffer[:n])
			if progress != nil && written > 0 {
				progress(uint64(written))
			}
			if writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := destination.Close(); err != nil {
		destination = nil
		return fmt.Errorf("close destination file: %w", err)
	}
	destination = nil
	return nil
}

func writeFull(writer io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := writer.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func blockDeviceSize(ctx context.Context, path string) (uint64, error) {
	output, err := exec.CommandContext(ctx, "blockdev", "--getsize64", path).Output()
	if err != nil {
		return 0, fmt.Errorf("read target size: %w", err)
	}
	var size uint64
	if _, err := fmt.Sscan(strings.TrimSpace(string(output)), &size); err != nil {
		return 0, fmt.Errorf("parse target size: %w", err)
	}
	return size, nil
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func humanBytes(bytes uint64) string {
	const unit = uint64(1024)
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	divisor, exponent := unit, 0
	for value := bytes / unit; value >= unit && exponent < 5; value /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(divisor), "KMGTPE"[exponent])
}

// Values from linux/openat2.h. openat2 has carried syscall number 437 on
// every architecture since Linux 5.6.
const (
	sysOpenat2        = 437
	resolveNoXDev     = 0x01
	resolveNoSymlinks = 0x04
	resolveBeneath    = 0x08
	oPath             = 0x200000
)

type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// openDirectoryNoFollow pins a directory itself rather than following a
// symbolic-link final component. O_PATH is used because some older kernels do
// not reliably reject a directory symlink for O_RDONLY|O_DIRECTORY|O_NOFOLLOW.
func openDirectoryNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s is not a real directory", path)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("create directory handle")
	}
	return file, nil
}

// openWithinRoot opens relative, a path beneath the already-open directory
// root, for reading. Every path component is resolved without following
// symbolic links and without escaping root. Linux 5.6 and newer use openat2;
// older kernels use an O_PATH descriptor walk and compare the final readable
// descriptor with the pinned final inode before accepting it.
func openWithinRoot(root *os.File, relative string) (*os.File, error) {
	if root == nil {
		return nil, errors.New("source root is not open")
	}
	if !filepath.IsLocal(relative) || relative == "." {
		return nil, fmt.Errorf("unsafe relative path: %s", relative)
	}
	how := openHow{
		Flags:   uint64(os.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK),
		Resolve: resolveNoXDev | resolveBeneath | resolveNoSymlinks,
	}
	pathPtr, err := syscall.BytePtrFromString(relative)
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall6(sysOpenat2, root.Fd(), uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno == 0 {
		file := os.NewFile(fd, relative)
		if file == nil {
			syscall.Close(int(fd))
			return nil, errors.New("create file handle")
		}
		return requireRegularFile(file, relative)
	}
	if errno != syscall.ENOSYS && errno != syscall.EINVAL {
		return nil, fmt.Errorf("open %s safely: %w", relative, errno)
	}

	parts := strings.Split(filepath.Clean(relative), string(os.PathSeparator))
	currentFD := int(root.Fd())
	ownedDirectoryFD := -1
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			if ownedDirectoryFD >= 0 {
				syscall.Close(ownedDirectoryFD)
			}
			return nil, fmt.Errorf("unsafe path component in %s", relative)
		}
		last := index == len(parts)-1
		pathFD, openErr := syscall.Openat(currentFD, part, oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			if ownedDirectoryFD >= 0 {
				syscall.Close(ownedDirectoryFD)
			}
			return nil, fmt.Errorf("open %s safely: %w", relative, openErr)
		}
		var pinned syscall.Stat_t
		if statErr := syscall.Fstat(pathFD, &pinned); statErr != nil {
			syscall.Close(pathFD)
			if ownedDirectoryFD >= 0 {
				syscall.Close(ownedDirectoryFD)
			}
			return nil, statErr
		}
		if last {
			if pinned.Mode&syscall.S_IFMT != syscall.S_IFREG {
				syscall.Close(pathFD)
				if ownedDirectoryFD >= 0 {
					syscall.Close(ownedDirectoryFD)
				}
				return nil, fmt.Errorf("%s is no longer a regular file", relative)
			}
			readFD, readErr := syscall.Openat(currentFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if ownedDirectoryFD >= 0 {
				syscall.Close(ownedDirectoryFD)
				ownedDirectoryFD = -1
			}
			if readErr != nil {
				syscall.Close(pathFD)
				return nil, fmt.Errorf("open %s for reading: %w", relative, readErr)
			}
			var opened syscall.Stat_t
			if statErr := syscall.Fstat(readFD, &opened); statErr != nil {
				syscall.Close(pathFD)
				syscall.Close(readFD)
				return nil, statErr
			}
			syscall.Close(pathFD)
			if opened.Mode&syscall.S_IFMT != syscall.S_IFREG || opened.Dev != pinned.Dev || opened.Ino != pinned.Ino {
				syscall.Close(readFD)
				return nil, fmt.Errorf("%s changed while it was being opened", relative)
			}
			file := os.NewFile(uintptr(readFD), relative)
			if file == nil {
				syscall.Close(readFD)
				return nil, errors.New("create file handle")
			}
			return file, nil
		}
		if pinned.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			syscall.Close(pathFD)
			if ownedDirectoryFD >= 0 {
				syscall.Close(ownedDirectoryFD)
			}
			return nil, fmt.Errorf("path component %s is not a real directory", part)
		}
		if ownedDirectoryFD >= 0 {
			syscall.Close(ownedDirectoryFD)
		}
		ownedDirectoryFD = pathFD
		currentFD = pathFD
	}
	return nil, fmt.Errorf("unsafe relative path: %s", relative)
}

func requireRegularFile(file *os.File, relative string) (*os.File, error) {
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is no longer a regular file", relative)
	}
	return file, nil
}
