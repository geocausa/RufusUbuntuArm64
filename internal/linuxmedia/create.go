//go:build linux

package linuxmedia

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type PersistentEvent struct {
	Stage   string
	Message string
	Path    string
	Done    uint64
	Total   uint64
}

type PersistentEventFunc func(PersistentEvent)

type PersistentCreateOptions struct {
	TargetSize         uint64
	ExpectedDeviceID   uint64
	ExpectedSource     sourcefile.Identity
	Architecture       string
	PersistenceSize    uint64
	VolumeLabel        string
	WorkDirectory      string
	BeforeDestructive  func(source *os.File) error
	ManifestMaxEntries int
	ManifestMaxBytes   uint64
}

type PersistentCreateResult struct {
	Layout       PersistentLayout      `json:"layout"`
	Detection    persistence.Detection `json:"detection"`
	Manifest     Manifest              `json:"manifest"`
	PatchedPaths []string              `json:"patched_paths"`
}

// CreatePersistent creates a fresh GPT/FAT32/ext4 persistent Linux USB. It is
// intentionally not called by the graphical writer. The caller must have
// already applied whole-disk policy, confirmation, and identity selection.
func CreatePersistent(ctx context.Context, isoPath, devicePath string, opts PersistentCreateOptions, emit PersistentEventFunc) (result PersistentCreateResult, returnErr error) {
	isoFile, err := sourcefile.OpenRegular(isoPath, opts.ExpectedSource)
	if err != nil {
		return result, err
	}
	defer isoFile.Close()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

	sourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", "Hashing the selected Linux image…")
	if err != nil {
		return result, fmt.Errorf("hash selected Linux image: %w", err)
	}
	for _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck"} {
		if _, err := exec.LookPath(name); err != nil {
			return result, fmt.Errorf("required program %q is not installed", name)
		}
	}

	target, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return result, fmt.Errorf("open target for persistent Linux creation: %w", err)
	}
	defer target.Close()
	if err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
		return result, err
	}
	if err := syscall.Flock(int(target.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return result, fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	defer syscall.Flock(int(target.Fd()), syscall.LOCK_UN) // best effort
	targetInfo, err := target.Stat()
	if err != nil {
		return result, fmt.Errorf("stat persistent Linux target: %w", err)
	}
	testTarget := targetInfo.Mode().IsRegular()

	if opts.TargetSize == 0 {
		opts.TargetSize, err = persistentBlockDeviceSize(ctx, devicePath)
		if err != nil {
			return result, err
		}
	}
	sectorSize, err := persistentLogicalSectorSize(ctx, devicePath, testTarget)
	if err != nil {
		return result, err
	}
	label, err := normalizePersistentLabel(opts.VolumeLabel)
	if err != nil {
		return result, err
	}

	workRoot := opts.WorkDirectory
	if workRoot == "" {
		workRoot = "/run"
	}
	workDir, err := os.MkdirTemp(workRoot, "rufusarm64-linux-persistent-")
	if err != nil {
		return result, fmt.Errorf("create persistent Linux workspace: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return result, fmt.Errorf("secure persistent Linux workspace: %w", err)
	}
	if !testTarget {
		if err := safety.EnsurePathNotOnTarget(workDir, devicePath); err != nil {
			_ = os.RemoveAll(workDir)
			return result, fmt.Errorf("persistent Linux workspace is unsafe: %w", err)
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
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup writable boot mount: %w", err))
			} else {
				mountedBoot = false
			}
		}
		if mountedISO {
			if err := runPersistentQuiet(cleanupCtx, "umount", "--", isoMount); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup Linux image mount: %w", err))
			} else {
				mountedISO = false
			}
		}
		if !mountedBoot && !mountedISO {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove persistent Linux workspace: %w", err))
			}
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

	sendPersistent(emit, PersistentEvent{Stage: "inspect", Message: "Inspecting Linux persistence compatibility and writable-media requirements…"})
	detection, err := persistence.Detect(os.DirFS(sourceRoot))
	if err != nil {
		return result, err
	}
	if !detection.Ready() {
		return result, fmt.Errorf("detected %s but its persistence contract is outside the supported experimental scope", detection.DisplayName)
	}
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
	layout, err := PlanPersistentLayout(opts.TargetSize, sectorSize, manifest.TotalBytes, opts.PersistenceSize, detection)
	if err != nil {
		return result, err
	}
	result = PersistentCreateResult{Layout: layout, Detection: detection, Manifest: manifest}

	preDestructiveDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Rechecking the Linux image before erasing the USB…")
	if err != nil {
		return result, err
	}
	if !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
		return result, errors.New("the selected Linux image changed during inspection; nothing was erased")
	}
	checkTarget := func() error {
		if err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
			return err
		}
		if err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {
			return err
		}
		if opts.BeforeDestructive != nil {
			if err := opts.BeforeDestructive(isoFile); err != nil {
				return fmt.Errorf("target safety check: %w", err)
			}
		}
		return nil
	}
	if err := checkTarget(); err != nil {
		return result, err
	}

	sendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout for writable Linux boot files and persistence…"})
	if err := runPersistent(ctx, emit, "wipefs", "--all", "--force", "--", devicePath); err != nil {
		return result, err
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := WritePersistentGPT(target, layout); err != nil {
		return result, fmt.Errorf("write persistent Linux GPT: %w", err)
	}
	if err := persistentRereadPartitionTable(ctx, devicePath, emit); err != nil {
		sendPersistent(emit, PersistentEvent{Stage: "partition", Message: fmt.Sprintf("Warning: could not force an immediate partition-table reread: %v", err)})
	}
	if err := checkTarget(); err != nil {
		return result, err
	}

	bootPartition, persistencePartition, err := persistentPartitionPaths(ctx, devicePath, layout, testTarget)
	if err != nil {
		return result, err
	}
	if err := unmountPersistentDeviceMounts(ctx, bootPartition); err != nil {
		return result, err
	}
	if err := unmountPersistentDeviceMounts(ctx, persistencePartition); err != nil {
		return result, err
	}

	if err := checkTarget(); err != nil {
		return result, err
	}
	sendPersistent(emit, PersistentEvent{Stage: "format", Message: fmt.Sprintf("Formatting the writable UEFI boot partition as FAT32 (%s)…", label)})
	if err := runPersistent(ctx, emit, "mkfs.vfat", "-F", "32", "-n", label, bootPartition); err != nil {
		return result, fmt.Errorf("format writable boot partition: %w", err)
	}
	if err := unmountPersistentDeviceMounts(ctx, bootPartition); err != nil {
		return result, err
	}

	destinationRoot := bootMount
	if testTarget && os.Getenv("RUFUS_TEST_BOOT_ROOT") != "" {
		destinationRoot, err = resolveEmptyTestRoot(os.Getenv("RUFUS_TEST_BOOT_ROOT"))
		if err != nil {
			return result, err
		}
	} else {
		if err := runPersistent(ctx, emit, "mount", "-t", "vfat", "-o", "rw,nosuid,nodev,noexec,umask=0077", "--", bootPartition, bootMount); err != nil {
			return result, fmt.Errorf("mount writable boot partition: %w", err)
		}
		mountedBoot = true
	}

	sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Copying and verifying the Linux media tree…", Total: manifest.TotalBytes})
	if err := CopyAndVerify(ctx, manifest, destinationRoot, CopyOptions{Event: func(event CopyEvent) {
		sendPersistent(emit, PersistentEvent{Stage: "copy", Message: "Copying and verifying the Linux media tree…", Path: event.Path, Done: event.Done, Total: event.Total})
	}}); err != nil {
		return result, err
	}
	patched, err := persistence.PatchBootTree(destinationRoot, detection)
	if err != nil {
		return result, fmt.Errorf("enable Linux persistence in the writable boot tree: %w", err)
	}
	result.PatchedPaths = patched
	activated, err := persistence.Detect(os.DirFS(destinationRoot))
	if err != nil {
		return result, fmt.Errorf("verify patched persistence boot configuration: %w", err)
	}
	if activated.Family != detection.Family || len(activated.PatchPaths) != 0 || len(activated.AlreadyEnabledPaths) == 0 {
		return result, errors.New("writable boot tree did not retain a fully enabled persistence contract")
	}
	for _, path := range patched {
		sendPersistent(emit, PersistentEvent{Stage: "boot", Message: "Enabled persistence in boot configuration", Path: path})
	}
	if err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {
		return result, fmt.Errorf("sync writable boot files: %w", err)
	}
	if mountedBoot {
		if err := runPersistent(ctx, emit, "umount", "--", bootMount); err != nil {
			return result, fmt.Errorf("unmount writable boot partition: %w", err)
		}
		mountedBoot = false
	}
	if err := runPersistent(ctx, emit, "blockdev", "--flushbufs", bootPartition); err != nil && !testTarget {
		return result, fmt.Errorf("flush writable boot partition: %w", err)
	}
	sendPersistent(emit, PersistentEvent{Stage: "check", Message: "Checking the FAT32 boot filesystem…"})
	if err := runPersistent(ctx, emit, "fsck.vfat", "-n", bootPartition); err != nil {
		return result, fmt.Errorf("FAT32 boot filesystem check failed: %w", err)
	}

	if err := checkTarget(); err != nil {
		return result, err
	}
	persistenceID := uint64(0)
	if !testTarget {
		persistenceID, err = safety.KernelDeviceID(persistencePartition)
		if err != nil {
			return result, fmt.Errorf("bind persistence partition identity: %w", err)
		}
	}
	if err := persistence.CreateFilesystem(ctx, persistencePartition, layout.Plan, persistence.FilesystemOptions{
		ExpectedDeviceID: persistenceID,
		ExpectedSize:     layout.Persistence.SizeBytes,
		WorkDirectory:    workRoot,
		BeforeDestructive: func(_ *os.File) error {
			return checkTarget()
		},
		Event: func(event persistence.FilesystemEvent) {
			sendPersistent(emit, PersistentEvent{Stage: event.Stage, Message: event.Message})
		},
	}); err != nil {
		return result, err
	}

	postDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Checking that the Linux image stayed unchanged…")
	if err != nil {
		return result, err
	}
	if !bytes.Equal(sourceDigest[:], postDigest[:]) {
		return result, errors.New("the selected Linux image changed while the USB was being created; recreate the USB")
	}
	if err := checkTarget(); err != nil {
		return result, err
	}
	if err := runPersistent(ctx, emit, "blockdev", "--flushbufs", devicePath); err != nil && !testTarget {
		return result, fmt.Errorf("flush persistent Linux USB buffers: %w", err)
	}
	if mountedISO {
		if err := runPersistent(ctx, emit, "umount", "--", isoMount); err != nil {
			return result, err
		}
		mountedISO = false
	}
	sendPersistent(emit, PersistentEvent{Stage: "complete", Message: "Experimental persistent Linux USB created and verified."})
	return result, nil
}

func hashPersistentSource(ctx context.Context, file *os.File, expected sourcefile.Identity, emit PersistentEventFunc, stage, message string) ([sha256.Size]byte, error) {
	last := time.Time{}
	digest, err := sourcefile.SHA256Open(ctx, file, func(done, total uint64) {
		if now := time.Now(); done == total || now.Sub(last) >= 200*time.Millisecond {
			last = now
			sendPersistent(emit, PersistentEvent{Stage: stage, Message: message, Done: done, Total: total})
		}
	})
	if err != nil {
		return digest, err
	}
	if err := sourcefile.VerifyPinned(file, expected); err != nil {
		return digest, err
	}
	return digest, nil
}

func normalizePersistentLabel(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		value = "RUFUS-LIVE"
	}
	if len(value) > 11 {
		return "", errors.New("FAT32 boot volume label must be at most 11 characters")
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("FAT32 boot volume label must use printable ASCII")
		}
	}
	if strings.ContainsAny(value, `"*+,./:;<=>?[\\]|`) {
		return "", errors.New("FAT32 boot volume label contains an invalid character")
	}
	return value, nil
}

func persistentBlockDeviceSize(ctx context.Context, path string) (uint64, error) {
	output, err := exec.CommandContext(ctx, "blockdev", "--getsize64", path).Output()
	if err != nil {
		return 0, fmt.Errorf("read target capacity: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("target reports an invalid capacity")
	}
	return value, nil
}

func persistentLogicalSectorSize(ctx context.Context, path string, testTarget bool) (uint64, error) {
	if testTarget && os.Getenv("RUFUS_TEST_SECTOR_SIZE") == "" {
		return 512, nil
	}
	output, err := exec.CommandContext(ctx, "blockdev", "--getss", path).Output()
	if err != nil {
		return 0, fmt.Errorf("read target logical sector size: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || value < 512 || value > 64*1024 || value&(value-1) != 0 {
		return 0, fmt.Errorf("unsupported target logical sector size %q", strings.TrimSpace(string(output)))
	}
	return value, nil
}

func persistentPartitionPaths(ctx context.Context, devicePath string, layout PersistentLayout, testTarget bool) (string, string, error) {
	if testTarget {
		boot := os.Getenv("RUFUS_TEST_BOOT_PARTITION")
		persist := os.Getenv("RUFUS_TEST_PERSIST_PARTITION")
		if boot == "" || persist == "" {
			return "", "", errors.New("test persistent partitions are not configured")
		}
		return boot, persist, nil
	}
	boot, err := waitPersistentPartition(ctx, devicePath, layout.Boot, 45*time.Second)
	if err != nil {
		return "", "", err
	}
	persist, err := waitPersistentPartition(ctx, devicePath, layout.Persistence, 45*time.Second)
	if err != nil {
		return "", "", err
	}
	return boot, persist, nil
}

func waitPersistentPartition(ctx context.Context, devicePath string, layout PartitionLayout, timeout time.Duration) (string, error) {
	candidate := persistentPartitionPath(devicePath, layout.Number)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if persistentPartitionMatches(candidate, layout) {
			return candidate, nil
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		output, err := exec.CommandContext(probeCtx, "lsblk", "-lnpo", "NAME,TYPE", "--", devicePath).Output()
		cancel()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 2 && fields[1] == "part" && persistentPartitionMatches(fields[0], layout) {
					return fields[0], nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("new partition %d did not appear with the expected geometry", layout.Number)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func persistentPartitionMatches(path string, layout PartitionLayout) bool {
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeDevice == 0 {
		return false
	}
	base := filepath.Base(path)
	start, err := readPersistentSysfsSectors(filepath.Join("/sys/class/block", base, "start"))
	if err != nil {
		return false
	}
	size, err := readPersistentSysfsSectors(filepath.Join("/sys/class/block", base, "size"))
	if err != nil {
		return false
	}
	return start*512 == layout.StartBytes && size*512 == layout.SizeBytes
}

func readPersistentSysfsSectors(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func persistentPartitionPath(devicePath string, index int) string {
	base := filepath.Base(devicePath)
	suffix := strconv.Itoa(index)
	if base != "" && base[len(base)-1] >= '0' && base[len(base)-1] <= '9' {
		return devicePath + "p" + suffix
	}
	return devicePath + suffix
}

func persistentRereadPartitionTable(ctx context.Context, devicePath string, emit PersistentEventFunc) error {
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lastErr = runPersistentQuiet(commandCtx, "blockdev", "--rereadpt", devicePath)
		cancel()
		if lastErr == nil {
			return nil
		}
		if attempt == 1 {
			sendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Waiting for the kernel to refresh the new partitions…"})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
		}
	}
	return lastErr
}

func unmountPersistentDeviceMounts(ctx context.Context, devicePath string) error {
	output, err := exec.CommandContext(ctx, "findmnt", "-rn", "-S", devicePath, "-o", "TARGET").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("inspect mounts for %s: %w", devicePath, err)
	}
	var mountpoints []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if value := strings.TrimSpace(scanner.Text()); value != "" {
			mountpoints = append(mountpoints, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	sort.SliceStable(mountpoints, func(i, j int) bool {
		return strings.Count(filepath.Clean(mountpoints[i]), string(os.PathSeparator)) > strings.Count(filepath.Clean(mountpoints[j]), string(os.PathSeparator))
	})
	for _, mountpoint := range mountpoints {
		if err := runPersistentQuiet(ctx, "umount", "--", mountpoint); err != nil {
			return fmt.Errorf("unmount %s from %s: %w", devicePath, mountpoint, err)
		}
	}
	return nil
}

func resolveEmptyTestRoot(path string) (string, error) {
	root, err := resolveRoot(path)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if len(entries) != 0 {
		return "", errors.New("test writable boot root must be empty")
	}
	return root, nil
}

func runPersistent(ctx context.Context, emit PersistentEventFunc, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(output.String()))
	}
	if text := strings.TrimSpace(output.String()); text != "" {
		for _, line := range strings.Split(text, "\n") {
			sendPersistent(emit, PersistentEvent{Stage: "log", Message: line})
		}
	}
	return nil
}

func runPersistentQuiet(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func sendPersistent(emit PersistentEventFunc, event PersistentEvent) {
	if emit != nil {
		emit(event)
	}
}
