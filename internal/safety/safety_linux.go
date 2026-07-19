//go:build linux

package safety

import (
	"bufio"
	"bytes"
	"context"
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
	"unsafe"

	"github.com/geocausa/RufusArm64/internal/device"
)

var (
	ErrNotBlockDevice = errors.New("target is not a block device")
	ErrNotBlockBacked = errors.New("filesystem is not backed by a conventional /dev block device")
)

func ResolveDevice(path string) (string, error) {
	if !strings.HasPrefix(path, "/dev/") {
		return "", fmt.Errorf("device path must be under /dev: %q", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve device path: %w", err)
	}
	if !strings.HasPrefix(resolved, "/dev/") {
		return "", fmt.Errorf("resolved device path escaped /dev: %q", resolved)
	}
	return resolved, nil
}

// ValidateTargetMetadata contains the policy checks that do not touch the host
// filesystem. Keeping it separate makes the destructive target policy directly
// testable.
func ValidateTargetMetadata(path string, dev device.BlockDevice, allowFixed bool) error {
	if dev.Path != path {
		return fmt.Errorf("device metadata path mismatch: selected=%s reported=%s", path, dev.Path)
	}
	if dev.Type != "disk" {
		return fmt.Errorf("refusing partition or non-disk target %s (lsblk type %q); select the whole disk", path, dev.Type)
	}
	if dev.ReadOnly {
		return fmt.Errorf("target %s is read-only", path)
	}
	if dev.Size == 0 {
		return fmt.Errorf("target %s reported an invalid zero-byte size", path)
	}
	if err := ValidateNoProtectedMounts(dev); err != nil {
		return err
	}
	if !allowFixed && !device.IsNormalRemovableTarget(dev) {
		return fmt.Errorf("target %s is not marked removable or USB; fixed and internal MMC/eMMC disks are hidden unless --allow-fixed is explicitly supplied", path)
	}
	return nil
}

// ValidateNoProtectedMounts refuses media that currently backs a system or user
// data mount. Normal desktop-mounted removable drives under /media, /run/media,
// or /mnt remain eligible and are unmounted later.
func ValidateNoProtectedMounts(dev device.BlockDevice) error {
	for _, node := range device.Flatten(dev) {
		for _, mountpoint := range node.Mountpoints {
			clean := filepath.Clean(strings.TrimSpace(mountpoint))
			if clean == "[SWAP]" || protectedMountpoint(clean) {
				return fmt.Errorf("refusing %s because %s is used by the running system at %s", dev.Path, node.Path, mountpoint)
			}
		}
	}
	return nil
}

func protectedMountpoint(path string) bool {
	if !filepath.IsAbs(path) {
		return true
	}
	// Only conventional removable-media mount roots are eligible for automatic
	// unmounting. A USB disk deliberately mounted elsewhere (for example /srv,
	// /data, or an application directory) is treated as system/user data.
	for _, root := range []string{"/media", "/run/media", "/mnt"} {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// EnsureOpenFileNotOnTarget compares the filesystem device of an already-open
// image with the selected disk and all reported descendants. Holding the source
// file open closes the path-replacement race that path-only checks cannot.
func EnsureOpenFileNotOnTarget(file *os.File, target device.BlockDevice) error {
	if file == nil {
		return errors.New("image file is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open image: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return errors.New("image is no longer a regular file")
	}
	fileDevice := uint64(stat.Dev)
	for _, node := range device.Flatten(target) {
		if node.Path == "" {
			continue
		}
		nodeInfo, err := os.Stat(node.Path)
		if err != nil {
			return fmt.Errorf("stat target component %s: %w", node.Path, err)
		}
		nodeStat, ok := nodeInfo.Sys().(*syscall.Stat_t)
		if !ok || nodeStat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
			return fmt.Errorf("target component %s is no longer a block device", node.Path)
		}
		if uint64(nodeStat.Rdev) == fileDevice {
			return fmt.Errorf("the selected image is open from the target disk %s; move it to another disk", target.Path)
		}
	}
	return nil
}

func ValidateExpectedIdentity(dev device.BlockDevice, expected string) error {
	if expected == "" {
		return nil
	}
	actual := device.IdentityToken(dev)
	if actual != expected {
		return fmt.Errorf("the selected drive changed after confirmation; refusing to continue (expected identity %s, now %s)", shortIdentity(expected), shortIdentity(actual))
	}
	return nil
}

func ValidateTarget(path string, dev device.BlockDevice, allowFixed bool) error {
	if err := ValidateTargetMetadata(path, dev, allowFixed); err != nil {
		return err
	}
	if _, err := KernelDeviceID(path); err != nil {
		return err
	}
	rootDisks, err := BackingDisksForPath("/")
	if err != nil {
		return fmt.Errorf("cannot safely identify the running root disk: %w", err)
	}
	if contains(rootDisks, filepath.Base(path)) {
		return fmt.Errorf("refusing to overwrite a disk that backs the running root filesystem: %s", path)
	}
	return nil
}

// RevalidateTarget refreshes lsblk metadata immediately before a destructive
// action. It detects hot-unplug/replug and /dev name reuse.
func RevalidateTarget(path, expectedIdentity string, allowFixed bool) (device.BlockDevice, uint64, error) {
	dev, err := device.Find(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	if err := ValidateExpectedIdentity(dev, expectedIdentity); err != nil {
		return device.BlockDevice{}, 0, err
	}
	if err := ValidateTarget(path, dev, allowFixed); err != nil {
		return device.BlockDevice{}, 0, err
	}
	kernelID, err := KernelDeviceID(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	return dev, kernelID, nil
}

// RevalidateOpenBoundTarget is used only after the selected whole disk has been
// opened and identity-bound. The pre-erase GUI snapshot is intentionally not
// recomputed after RufusArm64 changes the disk layout. The live /dev path must
// still resolve to the same kernel block device and pass the complete target
// policy, while the writer independently verifies its held descriptor.
func RevalidateOpenBoundTarget(path string, expectedKernelID uint64, allowFixed bool) (device.BlockDevice, uint64, error) {
	dev, err := device.Find(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	if err := ValidateTarget(path, dev, allowFixed); err != nil {
		return device.BlockDevice{}, 0, err
	}
	kernelID, err := KernelDeviceID(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	if expectedKernelID != 0 && kernelID != expectedKernelID {
		return device.BlockDevice{}, 0, errors.New("the selected kernel device changed after confirmation")
	}
	return dev, kernelID, nil
}

func KernelDeviceID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return 0, ErrNotBlockDevice
	}
	return uint64(stat.Rdev), nil
}

// blkGetSize64 is the BLKGETSIZE64 ioctl request as encoded on 64-bit Linux
// (_IOR(0x12, 114, size_t) with an 8-byte size_t). The project only targets
// 64-bit hosts; on a 32-bit build this constant would be wrong and the ioctl
// below would fail closed rather than misreport a size.
const blkGetSize64 = 0x80081272

// VerifyOpenDevice checks both the dev_t identity and a live block-size ioctl on
// an already-open target. The ioctl makes a long-held descriptor fail closed if
// its USB device was unplugged while Windows media was being prepared.
func VerifyOpenDevice(file *os.File, expectedID, expectedSize uint64) error {
	if expectedID == 0 {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return ErrNotBlockDevice
	}
	if uint64(stat.Rdev) != expectedID {
		return errors.New("the kernel device behind the selected path changed; refusing to write")
	}
	var size uint64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), blkGetSize64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return fmt.Errorf("the selected block device is no longer responding: %w", errno)
	}
	if size == 0 {
		return errors.New("the selected block device now reports zero capacity")
	}
	if expectedSize > 0 && size != expectedSize {
		return fmt.Errorf("the selected block device capacity changed from %d to %d bytes", expectedSize, size)
	}
	return nil
}

func VerifyOpenDeviceID(file *os.File, expected uint64) error {
	return VerifyOpenDevice(file, expected, 0)
}

// BackingDisksForPath returns every top-level kernel disk that backs the
// filesystem containing path. Returning all disks matters for mdraid and other
// storage stacks with more than one physical parent.
func BackingDisksForPath(path string) ([]string, error) {
	source, err := commandOutput("findmnt", "-n", "-o", "SOURCE", "--target", path)
	if err != nil {
		return nil, err
	}
	source = strings.TrimSpace(source)
	if bracket := strings.IndexByte(source, '['); bracket >= 0 {
		source = source[:bracket]
	}
	if source == "" || !strings.HasPrefix(source, "/dev/") {
		return nil, fmt.Errorf("%w: source=%q", ErrNotBlockBacked, source)
	}
	if resolved, err := filepath.EvalSymlinks(source); err == nil {
		source = resolved
	}

	output, err := commandOutput("lsblk", "-s", "-n", "-o", "NAME,TYPE", source)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[len(fields)-1] == "disk" {
			seen[fields[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse lsblk dependency output: %w", err)
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("lsblk found no top-level disk backing %s", source)
	}
	disks := make([]string, 0, len(seen))
	for name := range seen {
		disks = append(disks, name)
	}
	sort.Strings(disks)
	return disks, nil
}

func EnsurePathNotOnTarget(path, targetPath string) error {
	backingDisks, err := BackingDisksForPath(path)
	if err != nil {
		// tmpfs, overlay, and network filesystems cannot be the selected raw
		// target. Other discovery failures are treated as unsafe.
		if errors.Is(err, ErrNotBlockBacked) {
			return nil
		}
		return fmt.Errorf("cannot identify the path's backing disk: %w", err)
	}
	if contains(backingDisks, filepath.Base(targetPath)) {
		return fmt.Errorf("%s is stored on the target disk %s; move it to another disk before writing", path, targetPath)
	}
	return nil
}

func EnsureImageNotOnTarget(imagePath, targetPath string) error {
	return EnsurePathNotOnTarget(imagePath, targetPath)
}

func UnmountDescendants(dev device.BlockDevice) error {
	mountpoints := make([]string, 0)
	for _, node := range device.MountedDescendants(dev) {
		mountpoints = append(mountpoints, node.Mountpoints...)
	}
	// Unmount deepest mount paths first; lsblk tree order is not a mount-depth
	// guarantee.
	sort.SliceStable(mountpoints, func(i, j int) bool {
		return mountDepth(mountpoints[i]) > mountDepth(mountpoints[j])
	})
	for _, mountpoint := range mountpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "umount", "--", mountpoint)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("unmount %s: %w", mountpoint, ctx.Err())
			}
			return fmt.Errorf("unmount %s: %w: %s", mountpoint, err, strings.TrimSpace(stderr.String()))
		}
	}
	return nil
}

func EnsureNoMountedDescendants(path string) error {
	dev, err := device.Find(path)
	if err != nil {
		return err
	}
	mounted := device.MountedDescendants(dev)
	if len(mounted) == 0 {
		return nil
	}
	var descriptions []string
	for _, node := range mounted {
		for _, mountpoint := range node.Mountpoints {
			descriptions = append(descriptions, fmt.Sprintf("%s at %s", node.Path, mountpoint))
		}
	}
	return fmt.Errorf("target was mounted again before writing: %s", strings.Join(descriptions, ", "))
}

func WipeSignatures(ctx context.Context, path string) error {
	return runCommand(ctx, "wipefs", "--all", "--force", "--", path)
}

// FlushBuffers asks the kernel to flush and invalidate block buffers so a
// subsequent verification read is not satisfied solely from the write cache.
func FlushBuffers(ctx context.Context, path string) error {
	return runCommand(ctx, "blockdev", "--flushbufs", path)
}

func RequireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("raw disk writing requires root; rerun with sudo")
	}
	return nil
}

func RereadPartitionTable(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return runCommand(ctx, "blockdev", "--rereadpt", path)
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func commandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s: %w", name, ctx.Err())
		}
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func mountDepth(path string) int {
	clean := filepath.Clean(path)
	if clean == "/" {
		return 0
	}
	return strings.Count(clean, string(filepath.Separator))
}

func shortIdentity(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// CancellationContext watches a per-user marker file created by the graphical
// application. It provides a reliable cancellation path even when pkexec has
// changed the helper's UID and the unprivileged GUI can no longer signal it.
func CancellationContext(parent context.Context, cancelPath string) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(parent)
	if cancelPath == "" {
		return ctx, cancel, nil
	}
	uidText := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uidText == "" {
		cancel()
		return nil, nil, errors.New("--cancel-file is accepted only when launched through pkexec")
	}
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("invalid PKEXEC_UID: %w", err)
	}
	runtimeDir := filepath.Clean(filepath.Join("/run/user", uidText))
	runtimeInfo, err := os.Stat(runtimeDir)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("inspect user runtime directory: %w", err)
	}
	runtimeStat, ok := runtimeInfo.Sys().(*syscall.Stat_t)
	if !runtimeInfo.IsDir() || !ok || uint64(runtimeStat.Uid) != uid || runtimeInfo.Mode().Perm()&0o022 != 0 {
		cancel()
		return nil, nil, errors.New("the user runtime directory has unsafe ownership or permissions")
	}
	cleanPath := filepath.Clean(cancelPath)
	base := filepath.Base(cleanPath)
	if filepath.Dir(cleanPath) != runtimeDir || !strings.HasPrefix(base, "rufusarm64-") || !strings.HasSuffix(base, ".cancel") {
		cancel()
		return nil, nil, errors.New("invalid cancellation marker path")
	}
	if _, err := os.Lstat(cleanPath); err == nil {
		cancel()
		return nil, nil, fmt.Errorf("cancellation marker already exists: %s", cleanPath)
	} else if !os.IsNotExist(err) {
		cancel()
		return nil, nil, fmt.Errorf("inspect cancellation marker: %w", err)
	}

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				info, err := os.Lstat(cleanPath)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || uint64(stat.Uid) != uid {
					continue
				}
				cancel()
				return
			}
		}
	}()
	cleanup := func() {
		cancel()
		_ = os.Remove(cleanPath)
	}
	return ctx, cleanup, nil
}
