//go:build linux

package nonbootable

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/safety"
)

// DeviceOptions binds the production backend to the selected kernel block
// device. BeforeDestructive must refresh host policy and identity immediately
// before the first erase command.
type DeviceOptions struct {
	ExpectedDeviceID  uint64
	ExpectedSize      uint64
	BeforeDestructive func(*os.File) error
	PartitionTimeout  time.Duration
}

// ExecuteDevice runs the state machine through the production Linux backend.
func ExecuteDevice(ctx context.Context, plan Plan, options DeviceOptions) (Report, error) {
	backend := &linuxBackend{options: options}
	if backend.options.PartitionTimeout <= 0 {
		backend.options.PartitionTimeout = 30 * time.Second
	}
	report, runErr := Execute(ctx, plan, backend, time.Now)
	closeErr := backend.Close()
	if closeErr != nil {
		if runErr == nil {
			return Report{}, closeErr
		}
		return report, errors.Join(runErr, closeErr)
	}
	return report, runErr
}

type linuxBackend struct {
	options DeviceOptions
	target  *os.File
	locked  bool
}

func (backend *linuxBackend) Prepare(ctx context.Context, plan Plan, _ PartitionTable) error {
	for _, name := range append(append([]string(nil), plan.RequiredTools...), "wipefs", "blkid", "sync") {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required program %q is not installed", name)
		}
	}
	if backend.options.ExpectedSize == 0 {
		backend.options.ExpectedSize = plan.DeviceSizeBytes
	}
	if backend.options.ExpectedSize != plan.DeviceSizeBytes {
		return errors.New("backend target size does not match the reviewed plan")
	}
	file, err := safety.OpenReopenableDevice(plan.DevicePath)
	if err != nil {
		return fmt.Errorf("open target for guarded formatting: %w", err)
	}
	backend.target = file
	if err := safety.AcquireExclusiveFlock(ctx, file); err != nil {
		return fmt.Errorf("another storage operation appears to be using %s: %w", plan.DevicePath, err)
	}
	backend.locked = true
	if err := safety.VerifyOpenDevice(file, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes); err != nil {
		return err
	}
	if backend.options.BeforeDestructive != nil {
		if err := backend.options.BeforeDestructive(file); err != nil {
			return fmt.Errorf("final target safety check: %w", err)
		}
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxBackend) Erase(ctx context.Context, plan Plan, _ PartitionTable) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	_, err := runCommand(ctx, nil, "wipefs", "--all", "--force", "--", plan.DevicePath)
	return err
}

func (backend *linuxBackend) Partition(ctx context.Context, plan Plan, table PartitionTable, script string) (string, error) {
	if err := backend.verifyTarget(plan); err != nil {
		return "", err
	}
	if _, err := runCommand(ctx, []byte(script), "sfdisk", "--no-reread", "--force", "--wipe", "always", "--wipe-partitions", "always", "--", plan.DevicePath); err != nil {
		return "", err
	}
	if err := backend.target.Sync(); err != nil {
		return "", fmt.Errorf("sync partition table: %w", err)
	}
	// A reread failure can be transient while desktop services release stale
	// partition nodes. Exact table and kernel-node readback below remains the gate.
	_, _ = runCommand(ctx, nil, "blockdev", "--rereadpt", plan.DevicePath)
	return backend.waitForPartition(ctx, plan, table)
}

func (backend *linuxBackend) Format(ctx context.Context, plan Plan, _ PartitionTable, partitionPath string) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
		return err
	}
	name := ""
	args := make([]string, 0, 8)
	switch plan.Filesystem {
	case FilesystemFAT32:
		name = "mkfs.vfat"
		args = append(args, "-F", "32")
		if plan.Label != "" {
			args = append(args, "-n", plan.Label)
		}
	case FilesystemExFAT:
		name = "mkfs.exfat"
		if plan.Label != "" {
			args = append(args, "-n", plan.Label)
		}
	case FilesystemNTFS:
		name = "mkfs.ntfs"
		args = append(args, "-F", "-Q")
		if plan.Label != "" {
			args = append(args, "-L", plan.Label)
		}
	case FilesystemExt4:
		name = "mkfs.ext4"
		args = append(args, "-F")
		if plan.Label != "" {
			args = append(args, "-L", plan.Label)
		}
	default:
		return fmt.Errorf("unsupported filesystem %q", plan.Filesystem)
	}
	args = append(args, partitionPath)
	_, err := runCommand(ctx, nil, name, args...)
	return err
}

func (backend *linuxBackend) Verify(ctx context.Context, plan Plan, table PartitionTable, partitionPath string) (FilesystemState, error) {
	if err := backend.verifyTarget(plan); err != nil {
		return FilesystemState{}, err
	}
	if _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", partitionPath); err != nil {
		return FilesystemState{}, fmt.Errorf("flush formatted partition: %w", err)
	}
	checkName, checkArgs, err := filesystemCheck(plan.Filesystem, partitionPath)
	if err != nil {
		return FilesystemState{}, err
	}
	if _, err := runCommand(ctx, nil, checkName, checkArgs...); err != nil {
		return FilesystemState{}, fmt.Errorf("filesystem check failed: %w", err)
	}
	if err := backend.verifyPublishedTable(ctx, plan, table); err != nil {
		return FilesystemState{}, err
	}
	metadata, err := readBlkid(ctx, partitionPath)
	if err != nil {
		return FilesystemState{}, err
	}
	filesystemType := strings.ToLower(metadata["TYPE"])
	if filesystemType == "vfat" {
		filesystemType = FilesystemFAT32
	}
	sizeText, err := commandText(ctx, "blockdev", "--getsize64", partitionPath)
	if err != nil {
		return FilesystemState{}, err
	}
	size, err := strconv.ParseUint(strings.TrimSpace(sizeText), 10, 64)
	if err != nil {
		return FilesystemState{}, fmt.Errorf("parse formatted partition size: %w", err)
	}
	readOnlyText, err := commandText(ctx, "blockdev", "--getro", partitionPath)
	if err != nil {
		return FilesystemState{}, err
	}
	partition, err := device.Find(partitionPath)
	if err != nil {
		return FilesystemState{}, err
	}
	parent := filepath.Base(plan.DevicePath)
	if partition.Type != "part" || partition.ParentName != parent {
		return FilesystemState{}, fmt.Errorf("formatted partition is not bound to %s", plan.DevicePath)
	}
	state := FilesystemState{
		Path:       partitionPath,
		Type:       filesystemType,
		Label:      metadata["LABEL"],
		UUID:       metadata["UUID"],
		SizeBytes:  size,
		ReadOnly:   strings.TrimSpace(readOnlyText) != "0",
		ParentPath: plan.DevicePath,
	}
	if state.Type != plan.Filesystem || state.Label != plan.Label || state.SizeBytes != plan.PartitionSizeBytes || state.ReadOnly {
		return FilesystemState{}, fmt.Errorf("formatted filesystem does not match the reviewed plan: %+v", state)
	}
	return state, nil
}

func (backend *linuxBackend) Finish(ctx context.Context, plan Plan, table PartitionTable, filesystem FilesystemState) error {
	if err := backend.verifyTarget(plan); err != nil {
		return err
	}
	if err := backend.verifyPublishedTable(ctx, plan, table); err != nil {
		return err
	}
	if filesystem.ParentPath != plan.DevicePath || filesystem.SizeBytes != plan.PartitionSizeBytes {
		return errors.New("verified filesystem changed before final synchronization")
	}
	if err := backend.target.Sync(); err != nil {
		return fmt.Errorf("sync target: %w", err)
	}
	if _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", plan.DevicePath); err != nil {
		return fmt.Errorf("flush target: %w", err)
	}
	if _, err := runCommand(ctx, nil, "sync"); err != nil {
		return fmt.Errorf("system synchronization: %w", err)
	}
	return backend.verifyTarget(plan)
}

func (backend *linuxBackend) Close() error {
	if backend.target == nil {
		return nil
	}
	var result error
	if backend.locked {
		if err := syscall.Flock(int(backend.target.Fd()), syscall.LOCK_UN); err != nil {
			result = errors.Join(result, fmt.Errorf("unlock target: %w", err))
		}
	}
	if err := backend.target.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close target: %w", err))
	}
	backend.target = nil
	backend.locked = false
	return result
}

func (backend *linuxBackend) verifyTarget(plan Plan) error {
	if backend.target == nil {
		return errors.New("target is not open")
	}
	return safety.VerifyOpenDevice(backend.target, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes)
}

type sfdiskDocument struct {
	PartitionTable struct {
		Label      string `json:"label"`
		Device     string `json:"device"`
		Unit       string `json:"unit"`
		SectorSize uint64 `json:"sectorsize"`
		Partitions []struct {
			Node  string `json:"node"`
			Start uint64 `json:"start"`
			Size  uint64 `json:"size"`
			Type  string `json:"type"`
			Name  string `json:"name"`
		} `json:"partitions"`
	} `json:"partitiontable"`
}

func (backend *linuxBackend) waitForPartition(ctx context.Context, plan Plan, table PartitionTable) (string, error) {
	deadline := time.Now().Add(backend.options.PartitionTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		document, err := readSfdisk(ctx, plan.DevicePath)
		if err == nil {
			err = validateSfdiskDocument(document, plan, table)
		}
		if err == nil {
			path := document.PartitionTable.Partitions[0].Node
			if err = verifyKernelPartition(path, plan, table); err == nil {
				return path, nil
			}
		}
		lastErr = err
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("partition node did not reach the reviewed geometry: %w", lastErr)
}

func (backend *linuxBackend) verifyPublishedTable(ctx context.Context, plan Plan, table PartitionTable) error {
	document, err := readSfdisk(ctx, plan.DevicePath)
	if err != nil {
		return err
	}
	if err := validateSfdiskDocument(document, plan, table); err != nil {
		return err
	}
	return verifyKernelPartition(document.PartitionTable.Partitions[0].Node, plan, table)
}

func readSfdisk(ctx context.Context, devicePath string) (sfdiskDocument, error) {
	stdout, err := runCommand(ctx, nil, "sfdisk", "--json", "--", devicePath)
	if err != nil {
		return sfdiskDocument{}, err
	}
	var document sfdiskDocument
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	if err := decoder.Decode(&document); err != nil {
		return sfdiskDocument{}, fmt.Errorf("parse sfdisk JSON: %w", err)
	}
	return document, nil
}

func validateSfdiskDocument(document sfdiskDocument, plan Plan, table PartitionTable) error {
	actual := document.PartitionTable
	expectedLabel := "gpt"
	if plan.Scheme == SchemeMBR {
		expectedLabel = "dos"
	}
	if strings.ToLower(actual.Label) != expectedLabel || actual.Device != plan.DevicePath || actual.Unit != "sectors" {
		return errors.New("published partition-table envelope does not match the reviewed plan")
	}
	if actual.SectorSize != 0 && actual.SectorSize != table.SectorSize {
		return errors.New("published partition table reports a different logical sector size")
	}
	if len(actual.Partitions) != 1 {
		return fmt.Errorf("published partition table contains %d partitions, want exactly one", len(actual.Partitions))
	}
	partition := actual.Partitions[0]
	if partition.Start != table.StartSector || partition.Size != table.SizeSectors || !samePartitionType(partition.Type, table.PartitionType) {
		return errors.New("published partition geometry or type does not match the reviewed plan")
	}
	if plan.Scheme == SchemeGPT && partition.Name != "RUFUSARM64-DATA" {
		return errors.New("published GPT data partition name is not canonical")
	}
	return nil
}

func samePartitionType(actual, expected string) bool {
	actual = strings.ToLower(strings.TrimSpace(actual))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) <= 2 {
		actual = strings.TrimLeft(actual, "0")
		expected = strings.TrimLeft(expected, "0")
	}
	return actual == expected
}

func verifyKernelPartition(path string, plan Plan, table PartitionTable) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return errors.New("published partition path is not a block device")
	}
	partition, err := device.Find(path)
	if err != nil {
		return err
	}
	if partition.Type != "part" || partition.ParentName != filepath.Base(plan.DevicePath) || partition.Size != plan.PartitionSizeBytes {
		return errors.New("kernel partition identity, parent, or size does not match the reviewed plan")
	}
	name := filepath.Base(path)
	startText, err := os.ReadFile(filepath.Join("/sys/class/block", name, "start"))
	if err != nil {
		return fmt.Errorf("read kernel partition start: %w", err)
	}
	sizeText, err := os.ReadFile(filepath.Join("/sys/class/block", name, "size"))
	if err != nil {
		return fmt.Errorf("read kernel partition size: %w", err)
	}
	start512, err := strconv.ParseUint(strings.TrimSpace(string(startText)), 10, 64)
	if err != nil {
		return fmt.Errorf("parse kernel partition start: %w", err)
	}
	size512, err := strconv.ParseUint(strings.TrimSpace(string(sizeText)), 10, 64)
	if err != nil {
		return fmt.Errorf("parse kernel partition size: %w", err)
	}
	if start512 > ^uint64(0)/512 || size512 > ^uint64(0)/512 {
		return errors.New("kernel partition geometry overflows bytes")
	}
	if start512*512 != plan.PartitionStartBytes || size512*512 != plan.PartitionSizeBytes {
		return errors.New("kernel partition start or size does not match the reviewed byte geometry")
	}
	if table.PartitionNumber != 1 {
		return errors.New("only partition one is permitted")
	}
	return nil
}

func filesystemCheck(filesystem, path string) (string, []string, error) {
	switch filesystem {
	case FilesystemFAT32:
		return "fsck.vfat", []string{"-n", path}, nil
	case FilesystemExFAT:
		return "fsck.exfat", []string{"-n", path}, nil
	case FilesystemNTFS:
		return "ntfsfix", []string{"-n", path}, nil
	case FilesystemExt4:
		return "e2fsck", []string{"-f", "-n", path}, nil
	default:
		return "", nil, fmt.Errorf("unsupported filesystem %q", filesystem)
	}
}

func readBlkid(ctx context.Context, path string) (map[string]string, error) {
	stdout, err := runCommand(ctx, nil, "blkid", "-p", "-o", "export", "--", path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(stdout), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key != "" {
			values[key] = value
		}
	}
	if values["TYPE"] == "" {
		return nil, errors.New("blkid did not report a filesystem type")
	}
	return values, nil
}

func commandText(ctx context.Context, name string, args ...string) (string, error) {
	stdout, err := runCommand(ctx, nil, name, args...)
	return string(stdout), err
}

func runCommand(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
