//go:build linux

package windowstogo

import (
	"bufio"
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
)

func liveLogicalSectorSize(ctx context.Context, blockdev, devicePath string) (uint64, error) {
	output, err := runToolOutput(ctx, blockdev, 64*1024, "--getss", devicePath)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || (value != 512 && value != 4096) {
		return 0, fmt.Errorf("target reports unsupported logical sector size %q", strings.TrimSpace(string(output)))
	}
	return value, nil
}

func rereadPartitionTable(ctx context.Context, tools map[string]string, devicePath string) error {
	var lastErr error
	for attempt := 1; attempt <= 8; attempt++ {
		lastErr = runTool(ctx, tools["blockdev"], "--rereadpt", devicePath)
		if lastErr == nil {
			_ = runTool(ctx, tools["udevadm"], "settle", "--timeout=15")
			return nil
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		timer := time.NewTimer(time.Duration(attempt) * 250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
	return fmt.Errorf("refresh Windows To Go partition table: %w", lastErr)
}

func waitForPartition(ctx context.Context, tools map[string]string, devicePath string, partition Partition) (string, error) {
	candidate := partitionDevicePath(devicePath, partition.Number)
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if partitionMatchesPlan(candidate, partition) {
			return candidate, nil
		}
		output, err := runToolOutput(ctx, tools["lsblk"], 256*1024, "-lnpo", "NAME,TYPE", "--", devicePath)
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 2 && fields[1] == "part" && partitionMatchesPlan(fields[0], partition) {
					return fields[0], nil
				}
			}
			if err := scanner.Err(); err != nil {
				return "", err
			}
		}
		select {
		case <-ctx.Done():
			return "", context.Cause(ctx)
		case <-deadline.C:
			return "", fmt.Errorf("partition %d did not appear with the reviewed geometry", partition.Number)
		case <-ticker.C:
		}
	}
}

func partitionDevicePath(devicePath string, index int) string {
	base := filepath.Base(devicePath)
	if base != "" && base[len(base)-1] >= '0' && base[len(base)-1] <= '9' {
		return devicePath + "p" + strconv.Itoa(index)
	}
	return devicePath + strconv.Itoa(index)
}

func partitionMatchesPlan(path string, partition Partition) bool {
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeDevice == 0 {
		return false
	}
	base := filepath.Base(path)
	start, err := readSysfsSectors(filepath.Join("/sys/class/block", base, "start"))
	if err != nil {
		return false
	}
	size, err := readSysfsSectors(filepath.Join("/sys/class/block", base, "size"))
	if err != nil {
		return false
	}
	return start*512 == partition.StartBytes && size*512 == partition.SizeBytes
}

func readSysfsSectors(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func mountedTargets(ctx context.Context, findmnt, source string) ([]string, error) {
	command := exec.CommandContext(ctx, findmnt, "-rn", "-S", source, "-o", "TARGET")
	command.Dir = "/"
	command.Env = commandEnvironment()
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil, nil
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		return nil, fmt.Errorf("find mounts for %s: %w", source, err)
	}
	var targets []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" {
			targets = append(targets, target)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return strings.Count(filepath.Clean(targets[i]), string(filepath.Separator)) > strings.Count(filepath.Clean(targets[j]), string(filepath.Separator))
	})
	return targets, nil
}

func unmountAll(ctx context.Context, tools map[string]string, source string) error {
	targets, err := mountedTargets(ctx, tools["findmnt"], source)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := runTool(ctx, tools["umount"], "--", target); err != nil {
			return fmt.Errorf("unmount %s from %s: %w", source, target, err)
		}
	}
	return nil
}

func requireUnmounted(ctx context.Context, tools map[string]string, source string) error {
	targets, err := mountedTargets(ctx, tools["findmnt"], source)
	if err != nil {
		return err
	}
	if len(targets) != 0 {
		return fmt.Errorf("%s is still mounted at %s", source, strings.Join(targets, ", "))
	}
	return nil
}

func formatPartitions(ctx context.Context, tools map[string]string, plan Plan, espPath, osPath string) error {
	clusterSectors := uint64(1)
	if plan.LogicalSectorSize == 512 {
		clusterSectors = 2 // Rufus uses a 1 KiB ESP cluster on 512-byte media.
	}
	if err := runTool(ctx, tools["mkfs.vfat"], "-F", "32", "-s", strconv.FormatUint(clusterSectors, 10), espPath); err != nil {
		return fmt.Errorf("format unlabelled Windows To Go ESP: %w", err)
	}
	if err := runTool(ctx, tools["mkfs.ntfs"], "-F", "-Q", "-L", plan.OS.Label, "-c", "4096", osPath); err != nil {
		return fmt.Errorf("format Windows To Go NTFS partition: %w", err)
	}
	for _, path := range []string{espPath, osPath} {
		if err := runTool(ctx, tools["blockdev"], "--flushbufs", path); err != nil {
			return fmt.Errorf("flush formatted partition %s: %w", path, err)
		}
	}
	if err := verifyFilesystemProbe(ctx, tools, espPath, "vfat", ""); err != nil {
		return err
	}
	if err := verifyFilesystemProbe(ctx, tools, osPath, "ntfs", plan.OS.Label); err != nil {
		return err
	}
	return nil
}

func verifyFilesystemProbe(ctx context.Context, tools map[string]string, path, expectedType, expectedLabel string) error {
	output, err := runToolOutput(ctx, tools["blkid"], 64*1024, "-p", "-o", "export", path)
	if err != nil {
		return fmt.Errorf("probe filesystem %s: %w", path, err)
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			decoded, decodeErr := decodeBlkidExport(value)
			if decodeErr != nil {
				return fmt.Errorf("decode blkid %s value: %w", key, decodeErr)
			}
			values[key] = decoded
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if values["TYPE"] != expectedType {
		return fmt.Errorf("filesystem %s type %q does not match %q", path, values["TYPE"], expectedType)
	}
	if values["LABEL"] != expectedLabel {
		return fmt.Errorf("filesystem %s label %q does not match %q", path, values["LABEL"], expectedLabel)
	}
	return nil
}

func mountPrivate(ctx context.Context, tools map[string]string, source, target string, readOnly bool) error {
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	options := mode + ",nosuid,nodev,noexec,umask=0077"
	if err := runTool(ctx, tools["mount"], "-o", options, "--", source, target); err != nil {
		return err
	}
	targets, err := mountedTargets(ctx, tools["findmnt"], source)
	if err != nil {
		return err
	}
	if len(targets) != 1 || filepath.Clean(targets[0]) != filepath.Clean(target) {
		return fmt.Errorf("%s mount is not exclusive at %s", source, target)
	}
	return nil
}

func verifyReadOnlyLoopMount(ctx context.Context, findmnt, target string) error {
	output, err := runToolOutput(ctx, findmnt, 64*1024, "-rn", "-T", target, "-o", "TARGET,SOURCE,OPTIONS")
	if err != nil {
		return fmt.Errorf("inspect private ISO mount: %w", err)
	}
	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	if len(fields) < 3 || filepath.Clean(fields[0]) != filepath.Clean(target) || !strings.HasPrefix(fields[1], "/dev/loop") {
		return fmt.Errorf("private ISO mount has unexpected target or source: %q", line)
	}
	options := strings.Split(fields[2], ",")
	readOnly := false
	for _, option := range options {
		if option == "ro" {
			readOnly = true
		}
		if option == "rw" {
			return errors.New("private ISO mount is writable")
		}
	}
	if !readOnly {
		return errors.New("private ISO mount does not report read-only mode")
	}
	return nil
}

func syncFilesystem(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("syncfs path must be canonical and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	// syscall.Sync is available across the Linux architectures supported by the
	// project, whereas SYS_SYNCFS constants are architecture-dependent in older
	// Go toolchains. The mount descriptor above still proves the reviewed path
	// exists, and the transaction performs per-partition BLKFLSBUF after unmount.
	syscall.Sync()
	return nil
}

func decodeBlkidExport(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", errors.New("trailing blkid escape")
		}
		next := value[index+1]
		switch next {
		case ' ', '\\':
			result.WriteByte(next)
			index++
		case 'x':
			if index+3 >= len(value) {
				return "", errors.New("truncated blkid hexadecimal escape")
			}
			parsed, err := strconv.ParseUint(value[index+2:index+4], 16, 8)
			if err != nil {
				return "", fmt.Errorf("invalid blkid hexadecimal escape: %w", err)
			}
			result.WriteByte(byte(parsed))
			index += 3
		default:
			return "", fmt.Errorf("unsupported blkid escape \\%c", next)
		}
	}
	return result.String(), nil
}
