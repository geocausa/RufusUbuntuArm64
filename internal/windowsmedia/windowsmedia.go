//go:build linux

// Package windowsmedia creates UEFI-bootable Windows installation USB media.
// It targets the modern UEFI workflow used by Windows on ARM64 and x86-64: one
// GPT FAT32 ESP containing the ISO files. When install.wim or install.esd
// exceeds FAT32's per-file limit, wimlib splits it into install.swm parts that
// Windows Setup understands.
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

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const (
	fat32MaxFileSize  = uint64(4*1024*1024*1024 - 1)
	copyBufferSize    = 4 * 1024 * 1024
	minimumFreeMargin = uint64(256 * 1024 * 1024)
	splitPartMiB      = "3500"
	bundledWimlibPath = "/usr/lib/rufusarm64/wimlib-imagex"
)

// Options controls creation and post-write verification.
type Options struct {
	TargetSize        uint64
	Verify            bool
	ExpectedDeviceID  uint64
	ExpectedSource    sourcefile.Identity
	RequireARM64      bool
	VolumeLabel       string
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
	OtherBytes         uint64
	CopyBytes          uint64
	RequiredBytes      uint64
	ExistingAnswerPath string
	ExistingAnswerSize uint64
	AnswerFile         []byte
}

// Create destroys devicePath and creates Windows UEFI installation media from
// isoPath. The caller must already have applied whole-disk and system-disk
// safety policy. Create performs capacity, architecture, split-image, and
// identity checks before touching the target partition table.
func Create(ctx context.Context, isoPath, devicePath string, opts Options, emit EventFunc) (returnErr error) {
	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return err
	}
	defer isoFile.Close()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

	for _, name := range []string{
		"mount", "umount", "findmnt", "lsblk", "wipefs",
		"mkfs.vfat", "fsck.vfat", "sync", "blockdev",
	} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required program %q is not installed", name)
		}
	}

	lock, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open target for locking: %w", err)
	}
	defer lock.Close()
	if err := safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) // best effort

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
		// Never recursively remove a directory that may still be a writable USB
		// mount. If unmounting failed, leave the private directory in place and
		// report the cleanup error rather than risking deletion of media contents.
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
		return errors.New("this ISO contains only x86-64 Windows boot files and will not boot this ARM64 computer; choose an official Windows ARM64 ISO")
	}
	plan.AnswerFile, err = windowsconfig.Generate(plan.Architecture, opts.Customizations)
	if err != nil {
		return fmt.Errorf("prepare Windows setup options: %w", err)
	}
	finalizePlan(&plan)
	if opts.TargetSize == 0 {
		opts.TargetSize, err = blockDeviceSize(ctx, devicePath)
		if err != nil {
			return err
		}
	}
	// Reject obviously undersized media before spending several minutes splitting
	// the Windows payload. The exact split size is checked again afterwards.
	if opts.TargetSize < plan.RequiredBytes {
		return fmt.Errorf("the USB drive is too small: need at least %s, but the drive is %s", humanBytes(plan.RequiredBytes), humanBytes(opts.TargetSize))
	}
	if len(plan.ExistingSplitFiles) > 0 {
		if _, err := validateSplitParts(plan.ExistingSplitFiles); err != nil {
			return fmt.Errorf("validate ISO split Windows image: %w", err)
		}
	}

	// Split onto the computer's temporary filesystem before erasing the USB. This
	// validates every resulting part and its exact required capacity first.
	if plan.NeedsSplit {
		if _, err := wimlibExecutable(); err != nil {
			return err
		}
		temporaryMargin := plan.InstallSize / 10
		if temporaryMargin < minimumFreeMargin {
			temporaryMargin = minimumFreeMargin
		}
		if err := ensureAvailableSpace(splitDir, plan.InstallSize+temporaryMargin); err != nil {
			return err
		}
		send(emit, Event{Stage: "split", Message: "Preparing the large Windows installation image before erasing the USB…"})
		plan.SplitFiles, plan.SplitBytes, err = prepareSplitImage(ctx, plan.InstallPath, splitDir, emit)
		if err != nil {
			return err
		}
		finalizePlan(&plan)
		if opts.TargetSize < plan.RequiredBytes {
			return fmt.Errorf("the USB drive is too small after preparing the Windows image: need at least %s, but the drive is %s", humanBytes(plan.RequiredBytes), humanBytes(opts.TargetSize))
		}
	}
	send(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Windows %s installation media detected; approximately %s will be written.", plan.Architecture, humanBytes(plan.CopyBytes))})

	checkTarget := func() error {
		if err := sourcefile.Verify(isoFile, opts.ExpectedSource); err != nil {
			return err
		}
		if err := safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
			return err
		}
		if opts.BeforeDestructive != nil {
			if err := opts.BeforeDestructive(isoFile); err != nil {
				return fmt.Errorf("target safety check: %w", err)
			}
		}
		return nil
	}
	runOnTarget := func(name string, args ...string) error {
		if err := checkTarget(); err != nil {
			return err
		}
		return run(ctx, emit, name, args...)
	}

	label, err := normalizeVolumeLabel(opts.VolumeLabel)
	if err != nil {
		return err
	}
	sectorSize, err := logicalSectorSize(ctx, devicePath)
	if err != nil {
		return err
	}
	send(emit, Event{Stage: "partition", Message: "Creating a GPT partition table…"})
	if err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {
		return err
	}
	if err := checkTarget(); err != nil {
		return err
	}
	layout, err := writeSinglePartitionGPT(lock, opts.TargetSize, sectorSize, label)
	if err != nil {
		return fmt.Errorf("create GPT partition table: %w", err)
	}
	if err := checkTarget(); err != nil {
		return err
	}
	// Notify only this target. Unlike partprobe/libparted, this does not wait on
	// the machine-wide udev queue and therefore cannot be blocked by an unrelated
	// device event. Retry transient EBUSY-style failures before waiting for the
	// target's partition node.
	if err := rereadPartitionTable(ctx, devicePath, emit); err != nil {
		return err
	}
	if err := checkTarget(); err != nil {
		return err
	}

	partition, err := waitForPartition(ctx, devicePath, layout, 30*time.Second)
	if err != nil {
		return err
	}
	// Desktop automounters can race with partition creation. Unmount by device
	// before formatting and again before mounting at our private mountpoint.
	if err := unmountDeviceMounts(ctx, partition); err != nil {
		return err
	}
	send(emit, Event{Stage: "format", Message: fmt.Sprintf("Formatting the USB as FAT32 (%s)…", label)})
	if err := checkTarget(); err != nil {
		return err
	}
	if err := run(ctx, emit, "mkfs.vfat", "-F", "32", "-n", label, partition); err != nil {
		return err
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
			return verifyTree(verifyCtx, isoMount, usbMount, plan, emit)
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
	send(emit, Event{Stage: "check", Message: "Checking the FAT32 filesystem…"})
	if err := run(ctx, emit, "fsck.vfat", "-n", partition); err != nil {
		return fmt.Errorf("FAT32 filesystem check failed: %w", err)
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
	architecture := "UEFI"
	switch {
	case arm64 && x64:
		architecture = "ARM64/x86-64 UEFI"
	case arm64:
		architecture = "ARM64 UEFI"
	case x64:
		architecture = "x86-64 UEFI"
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
		plan.NeedsSplit = plan.InstallSize > fat32MaxFileSize
	}

	seenFATPaths := make(map[string]string)
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsupported symbolic link in ISO: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in ISO: %s", path)
		}
		size := uint64(info.Size())
		if samePath(path, plan.InstallPath) {
			return nil
		}
		if size > fat32MaxFileSize {
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("the ISO contains another file too large for FAT32: %s (%s)", filepath.ToSlash(rel), humanBytes(size))
		}
		plan.OtherBytes += size
		return nil
	})
	if walkErr != nil {
		return mediaPlan{}, walkErr
	}
	finalizePlan(&plan)
	return plan, nil
}

func finalizePlan(plan *mediaPlan) {
	installOutput := plan.InstallSize
	if plan.NeedsSplit && plan.SplitBytes > 0 {
		installOutput = plan.SplitBytes
	}
	otherBytes := plan.OtherBytes
	if len(plan.AnswerFile) > 0 && plan.ExistingAnswerSize <= otherBytes {
		otherBytes -= plan.ExistingAnswerSize
		otherBytes += uint64(len(plan.AnswerFile))
	}
	plan.CopyBytes = otherBytes + installOutput
	margin := plan.CopyBytes / 10 // 10% for FAT metadata and split-image variance.
	if margin < minimumFreeMargin {
		margin = minimumFreeMargin
	}
	plan.RequiredBytes = plan.CopyBytes + margin + 2*1024*1024
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

func verifySplitImage(ctx context.Context, parts []string, emit EventFunc) error {
	if len(parts) == 0 {
		return errors.New("no split WIM parts were supplied")
	}
	args := []string{"verify", parts[0]}
	for _, part := range parts {
		// An exact path is also a valid wimlib --ref glob, and avoids relying on
		// shell expansion or filename case.
		args = append(args, "--ref="+part)
	}
	wimlib, err := wimlibExecutable()
	if err != nil {
		return err
	}
	return run(ctx, emit, wimlib, args...)
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
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
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
		total += size
	}
	return total, nil
}

func copyTree(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, progress func(uint64)) error {
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
			return fmt.Errorf("unsupported file in ISO: %s", path)
		}
		if err := copyFile(ctx, path, destination, progress); err != nil {
			return fmt.Errorf("copy %s: %w", filepath.ToSlash(relative), err)
		}
		_ = os.Chtimes(destination, info.ModTime(), info.ModTime())
		return nil
	})
}

func verifyTree(ctx context.Context, sourceRoot, destinationRoot string, plan mediaPlan, emit EventFunc) error {
	total := plan.CopyBytes
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
	return nil
}

func compareFiles(leftPath, rightPath string) (uint64, error) {
	leftInfo, err := os.Stat(leftPath)
	if err != nil {
		return 0, err
	}
	rightInfo, err := os.Stat(rightPath)
	if err != nil {
		return 0, err
	}
	if leftInfo.Size() != rightInfo.Size() {
		return 0, fmt.Errorf("size mismatch: source=%d destination=%d", leftInfo.Size(), rightInfo.Size())
	}
	leftHash, err := fileSHA256(leftPath)
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
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, copyBufferSize)); err != nil {
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func wimlibExecutable() (string, error) {
	if info, err := os.Stat(bundledWimlibPath); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		return bundledWimlibPath, nil
	}
	if path, err := exec.LookPath("wimlib-imagex"); err == nil {
		return path, nil
	}
	return "", errors.New("this Windows ISO needs WIM support, but wimlib-imagex is unavailable; install Ubuntu's 'wimtools' package or use a RufusArm64 build that includes the bundled WIM engine")
}

func normalizeVolumeLabel(value string) (string, error) {
	label := strings.ToUpper(strings.TrimSpace(value))
	if label == "" {
		label = "RUFUSARM64"
	}
	if len(label) > 11 {
		return "", errors.New("FAT32 volume label must contain at most 11 ASCII characters")
	}
	for _, r := range label {
		if r < 0x20 || r > 0x7e || strings.ContainsRune(`"*/:<>?\\|+,.;=[]`, r) {
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

func waitForPartition(ctx context.Context, devicePath string, layout gptLayout, timeout time.Duration) (string, error) {
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	candidate := firstPartitionPath(devicePath)
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

func partitionMatchesLayout(partitionPath string, layout gptLayout) bool {
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
	base := filepath.Base(devicePath)
	if base != "" && base[len(base)-1] >= '0' && base[len(base)-1] <= '9' {
		return devicePath + "p1"
	}
	return devicePath + "1"
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

func copyFile(ctx context.Context, sourcePath, destinationPath string, progress func(uint64)) (returnErr error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
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
