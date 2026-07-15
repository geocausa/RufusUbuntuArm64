//go:build linux

// Package windowsmedia creates UEFI-bootable Windows installation USB media.
// It deliberately targets the modern UEFI workflow used by Windows on ARM64
// and x86-64: one GPT FAT32 ESP containing the ISO files. When install.wim or
// install.esd exceeds FAT32's per-file limit, wimlib splits it into install.swm
// parts that Windows Setup understands.
package windowsmedia

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	fat32MaxFileSize  = uint64(4*1024*1024*1024 - 1)
	copyBufferSize    = 4 * 1024 * 1024
	minimumFreeMargin = uint64(128 * 1024 * 1024)
)

type Options struct {
	TargetSize uint64
	Verify     bool
}

type Event struct {
	Stage   string
	Message string
	Done    uint64
	Total   uint64
}

type EventFunc func(Event)

type mediaPlan struct {
	InstallPath     string
	InstallRelative string
	InstallSize     uint64
	NeedsSplit      bool
	Architecture    string
	CopyBytes       uint64
	RequiredBytes   uint64
}

// Create destroys devicePath and creates Windows UEFI installation media from
// isoPath. The caller must already have applied whole-disk and system-disk
// safety policy. Create performs its own capacity and ISO-layout checks before
// touching the target partition table.
func Create(ctx context.Context, isoPath, devicePath string, opts Options, emit EventFunc) error {
	for _, name := range []string{"mount", "umount", "wipefs", "parted", "partprobe", "udevadm", "mkfs.vfat", "sync"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required program %q is not installed", name)
		}
	}

	lock, err := os.OpenFile(devicePath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open target for locking: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another writer appears to be using %s: %w", devicePath, err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) // best effort

	workDir, err := os.MkdirTemp("", "rufusarm64-")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(workDir)
	isoMount := filepath.Join(workDir, "iso")
	usbMount := filepath.Join(workDir, "usb")
	if err := os.MkdirAll(isoMount, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(usbMount, 0o700); err != nil {
		return err
	}

	mountedISO := false
	mountedUSB := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if mountedUSB {
			_ = runQuiet(cleanupCtx, "umount", "--", usbMount)
		}
		if mountedISO {
			_ = runQuiet(cleanupCtx, "umount", "--", isoMount)
		}
	}()

	send(emit, Event{Stage: "inspect", Message: "Opening and checking the Windows ISO…"})
	if err := run(ctx, emit, "mount", "-o", "loop,ro", "--", isoPath, isoMount); err != nil {
		return fmt.Errorf("mount ISO: %w", err)
	}
	mountedISO = true

	plan, err := inspectMountedISO(isoMount)
	if err != nil {
		return err
	}
	if plan.NeedsSplit {
		if _, err := exec.LookPath("wimlib-imagex"); err != nil {
			return errors.New("this Windows ISO needs WIM splitting; install the Ubuntu package 'wimtools' and try again")
		}
	}
	if opts.TargetSize == 0 {
		opts.TargetSize, err = blockDeviceSize(ctx, devicePath)
		if err != nil {
			return err
		}
	}
	if opts.TargetSize < plan.RequiredBytes {
		return fmt.Errorf("the USB drive is too small: need at least %s, but the drive is %s", humanBytes(plan.RequiredBytes), humanBytes(opts.TargetSize))
	}
	send(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Windows %s installation media detected; approximately %s will be written.", plan.Architecture, humanBytes(plan.CopyBytes))})

	send(emit, Event{Stage: "partition", Message: "Creating a GPT partition table…"})
	if err := run(ctx, emit, "wipefs", "--all", "--force", "--", devicePath); err != nil {
		return err
	}
	if err := run(ctx, emit, "parted", "--script", "--", devicePath, "mklabel", "gpt"); err != nil {
		return err
	}
	if err := run(ctx, emit, "parted", "--script", "--", devicePath, "mkpart", "RUFUSARM64", "fat32", "1MiB", "100%"); err != nil {
		return err
	}
	if err := run(ctx, emit, "parted", "--script", "--", devicePath, "set", "1", "esp", "on"); err != nil {
		return err
	}
	_ = run(ctx, emit, "partprobe", "--", devicePath)
	_ = run(ctx, emit, "udevadm", "settle")

	partition, err := waitForPartition(ctx, devicePath, 20*time.Second)
	if err != nil {
		return err
	}
	_ = runQuiet(ctx, "umount", "--", partition)

	send(emit, Event{Stage: "format", Message: "Formatting the USB as FAT32…"})
	if err := run(ctx, emit, "mkfs.vfat", "-F", "32", "-n", "RUFUSARM64", partition); err != nil {
		return err
	}
	_ = runQuiet(ctx, "umount", "--", partition)
	if err := run(ctx, emit, "mount", "--", partition, usbMount); err != nil {
		return err
	}
	mountedUSB = true

	send(emit, Event{Stage: "copy", Message: "Copying Windows setup files…", Total: plan.CopyBytes})
	var copied uint64
	report := func(delta uint64) {
		copied += delta
		send(emit, Event{Stage: "copy", Message: "Copying Windows setup files…", Done: copied, Total: plan.CopyBytes})
	}
	if err := copyTree(ctx, isoMount, usbMount, plan.InstallPath, report); err != nil {
		return err
	}

	if plan.InstallPath != "" {
		sourcesDir := filepath.Join(usbMount, "sources")
		if err := os.MkdirAll(sourcesDir, 0o755); err != nil {
			return err
		}
		if !plan.NeedsSplit {
			dest := filepath.Join(sourcesDir, strings.ToLower(filepath.Base(plan.InstallPath)))
			if err := copyFile(ctx, plan.InstallPath, dest, report); err != nil {
				return fmt.Errorf("copy Windows installation image: %w", err)
			}
		} else {
			send(emit, Event{Stage: "split", Message: "Splitting the large Windows installation image for FAT32…"})
			dest := filepath.Join(sourcesDir, "install.swm")
			if err := run(ctx, emit, "wimlib-imagex", "split", plan.InstallPath, dest, "3800"); err != nil {
				return err
			}
			copied += plan.InstallSize
			send(emit, Event{Stage: "copy", Message: "Windows installation image prepared.", Done: copied, Total: plan.CopyBytes})
		}
	}

	send(emit, Event{Stage: "sync", Message: "Flushing all pending writes safely…"})
	if err := run(ctx, emit, "sync"); err != nil {
		return err
	}

	if opts.Verify {
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files…"})
		if err := verifyTree(ctx, isoMount, usbMount, plan, emit); err != nil {
			return err
		}
	}
	if err := run(ctx, emit, "umount", "--", usbMount); err != nil {
		return err
	}
	mountedUSB = false
	if err := run(ctx, emit, "umount", "--", isoMount); err != nil {
		return err
	}
	mountedISO = false
	send(emit, Event{Stage: "complete", Message: "Windows installation USB created successfully."})
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

	installPath, hasInstall := findRelativeCaseInsensitive(root, "sources/install.wim")
	if !hasInstall {
		installPath, hasInstall = findRelativeCaseInsensitive(root, "sources/install.esd")
	}

	plan := mediaPlan{InstallPath: installPath, Architecture: architecture}
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

	var regularBytes uint64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
			regularBytes += size
			return nil
		}
		if size > fat32MaxFileSize {
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("the ISO contains another file too large for FAT32: %s (%s)", filepath.ToSlash(rel), humanBytes(size))
		}
		regularBytes += size
		return nil
	})
	if err != nil {
		return mediaPlan{}, err
	}
	plan.CopyBytes = regularBytes
	margin := regularBytes / 20
	if margin < minimumFreeMargin {
		margin = minimumFreeMargin
	}
	plan.RequiredBytes = regularBytes + margin + 2*1024*1024
	return plan, nil
}

func copyTree(ctx context.Context, sourceRoot, destinationRoot, excludedPath string, progress func(uint64)) error {
	return filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if samePath(path, excludedPath) {
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
	var total uint64
	err := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || samePath(path, plan.InstallPath) {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += uint64(info.Size())
		return nil
	})
	if err != nil {
		return err
	}
	if plan.InstallPath != "" && !plan.NeedsSplit {
		total += plan.InstallSize
	}

	var done uint64
	err = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || samePath(path, plan.InstallPath) {
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
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files…", Done: done, Total: total})
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
		send(emit, Event{Stage: "verify", Message: "Verifying copied setup files…", Done: done, Total: total})
	}
	if plan.NeedsSplit {
		firstPart := filepath.Join(destinationRoot, "sources", "install.swm")
		if _, err := os.Stat(firstPart); err != nil {
			return fmt.Errorf("split Windows image is missing: %w", err)
		}
		send(emit, Event{Stage: "verify", Message: "Validating the split Windows image…"})
		if err := run(ctx, emit, "wimlib-imagex", "verify", firstPart); err != nil {
			return fmt.Errorf("validate split Windows image: %w", err)
		}
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
	done := make(chan struct{}, 2)
	relay := func(reader io.Reader) {
		defer func() { done <- struct{}{} }()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
			if line != "" {
				send(emit, Event{Stage: "log", Message: line})
			}
		}
	}
	go relay(stdout)
	go relay(stderr)
	<-done
	<-done
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func waitForPartition(ctx context.Context, devicePath string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, "lsblk", "-lnpo", "NAME,TYPE", "--", devicePath)
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 2 && fields[1] == "part" {
					return fields[0], nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return "", errors.New("the new USB partition did not appear")
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
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer destination.Close()
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
	return destination.Sync()
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
