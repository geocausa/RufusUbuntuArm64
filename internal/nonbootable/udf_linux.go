//go:build linux

package nonbootable

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	udfRevision            = "2.01"
	udfSuperMagic   int64  = 0x15013346
	udfStatReadOnly uint64 = 0x1
	udfStatNoSuid   uint64 = 0x2
	udfStatNoDev    uint64 = 0x4
	udfStatNoExec   uint64 = 0x8
)

var udfVerificationWorkspaceRoot = "/run"

func inspectUDF(ctx context.Context, plan Plan, path string) (map[string]string, error) {
	stdout, err := runCommand(
		ctx,
		nil,
		"udfinfo",
		"--utf8",
		fmt.Sprintf("--blocksize=%d", plan.LogicalSectorSize),
		"--",
		path,
	)
	if err != nil {
		return nil, fmt.Errorf("inspect UDF descriptors: %w", err)
	}
	metadata, err := parseUDFInfo(stdout)
	if err != nil {
		return nil, err
	}
	if err := validateUDFInfo(metadata, plan); err != nil {
		return nil, err
	}
	return metadata, nil
}

func parseUDFInfo(output []byte) (map[string]string, error) {
	values := make(map[string]string)
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			continue
		}
		// Descriptor extent lines repeat "start" and are intentionally ignored.
		if key == "start" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("udfinfo repeated metadata key %q", key)
		}
		values[key] = value
	}
	for _, key := range []string{
		"label", "uuid", "lvid", "blocksize", "blocks", "behindblocks",
		"numfiles", "numdirs", "udfrev", "udfwriterev", "integrity",
		"accesstype", "softwriteprotect", "hardwriteprotect",
	} {
		if _, ok := values[key]; !ok {
			return nil, fmt.Errorf("udfinfo omitted required metadata %q", key)
		}
	}
	return values, nil
}

func validateUDFInfo(values map[string]string, plan Plan) error {
	if values["label"] != plan.Label || values["lvid"] != plan.Label {
		return fmt.Errorf("UDF logical-volume label does not match the reviewed plan: label=%q lvid=%q", values["label"], values["lvid"])
	}
	uuid := values["uuid"]
	decoded, err := hex.DecodeString(uuid)
	if err != nil || len(decoded) != 8 || uuid != strings.ToLower(uuid) {
		return fmt.Errorf("UDF UUID %q is not 16 lowercase hexadecimal digits", uuid)
	}
	blockSize, err := parseUDFUint(values, "blocksize")
	if err != nil {
		return err
	}
	if blockSize != plan.LogicalSectorSize {
		return fmt.Errorf("UDF block size %d does not match logical sector size %d", blockSize, plan.LogicalSectorSize)
	}
	blocks, err := parseUDFUint(values, "blocks")
	if err != nil {
		return err
	}
	if blocks > ^uint64(0)/blockSize || blocks*blockSize != plan.PartitionSizeBytes {
		return fmt.Errorf("UDF geometry %d blocks x %d bytes does not match partition size %d", blocks, blockSize, plan.PartitionSizeBytes)
	}
	for _, key := range []string{"behindblocks", "numfiles"} {
		value, err := parseUDFUint(values, key)
		if err != nil {
			return err
		}
		if value != 0 {
			return fmt.Errorf("fresh UDF metadata %s=%d, want 0", key, value)
		}
	}
	directories, err := parseUDFUint(values, "numdirs")
	if err != nil {
		return err
	}
	if directories != 1 {
		return fmt.Errorf("fresh UDF metadata numdirs=%d, want 1", directories)
	}
	if values["udfrev"] != udfRevision || values["udfwriterev"] != udfRevision {
		return fmt.Errorf("UDF revision read=%q write=%q, want %s", values["udfrev"], values["udfwriterev"], udfRevision)
	}
	if values["integrity"] != "closed" {
		return fmt.Errorf("UDF integrity is %q, want closed", values["integrity"])
	}
	if values["accesstype"] != "overwritable" {
		return fmt.Errorf("UDF access type is %q, want overwritable", values["accesstype"])
	}
	if values["softwriteprotect"] != "no" || values["hardwriteprotect"] != "no" {
		return fmt.Errorf("UDF write-protection flags are soft=%q hard=%q", values["softwriteprotect"], values["hardwriteprotect"])
	}
	return nil
}

func validateUDFBlkid(blkid, udf map[string]string, plan Plan) error {
	if strings.ToLower(blkid["TYPE"]) != FilesystemUDF {
		return fmt.Errorf("blkid reported filesystem type %q, want udf", blkid["TYPE"])
	}
	if blkid["VERSION"] != udfRevision {
		return fmt.Errorf("blkid reported UDF revision %q, want %s", blkid["VERSION"], udfRevision)
	}
	if blkid["LABEL"] != plan.Label || blkid["LOGICAL_VOLUME_ID"] != plan.Label {
		return fmt.Errorf("blkid UDF label evidence does not match the reviewed label %q", plan.Label)
	}
	if blkid["UUID"] != udf["uuid"] {
		return fmt.Errorf("blkid UDF UUID %q does not match udfinfo UUID %q", blkid["UUID"], udf["uuid"])
	}
	for _, key := range []string{"BLOCK_SIZE", "FSBLOCKSIZE"} {
		value, err := strconv.ParseUint(strings.TrimSpace(blkid[key]), 10, 64)
		if err != nil || value != plan.LogicalSectorSize {
			return fmt.Errorf("blkid %s=%q does not match logical sector size %d", key, blkid[key], plan.LogicalSectorSize)
		}
	}
	return nil
}

func parseUDFUint(values map[string]string, key string) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(values[key]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse udfinfo %s=%q: %w", key, values[key], err)
	}
	return value, nil
}

func verifyReadOnlyUDFMount(ctx context.Context, partitionPath string) (returnErr error) {
	if os.Geteuid() != 0 {
		return errors.New("independent UDF mount verification requires root privileges")
	}
	mountExecutable, err := trustedexec.Resolve("mount")
	if err != nil {
		return fmt.Errorf("resolve trusted mount utility: %w", err)
	}
	workspaceRoot, err := openUDFVerificationRoot(udfVerificationWorkspaceRoot)
	if err != nil {
		return err
	}
	defer workspaceRoot.Close()
	workspaceProc := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), workspaceRoot.Fd())
	created, err := os.MkdirTemp(workspaceProc, "rufusarm64-udf-verify-")
	if err != nil {
		return fmt.Errorf("create UDF verification workspace: %w", err)
	}
	workspace := filepath.Join(udfVerificationWorkspaceRoot, filepath.Base(created))
	mounted := false
	defer func() {
		if mounted {
			returnErr = errors.Join(returnErr, fmt.Errorf("UDF verification mount remained active at %s", workspace))
			return
		}
		returnErr = errors.Join(returnErr, os.RemoveAll(workspace))
	}()
	if err := os.Chmod(workspace, 0o700); err != nil {
		return fmt.Errorf("secure UDF verification workspace: %w", err)
	}
	mountpoint := filepath.Join(workspace, "root")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		return fmt.Errorf("create UDF verification mountpoint: %w", err)
	}
	before, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open UDF verification mountpoint: %w", err)
	}
	beforeMountID, idErr := udfDescriptorMountID(before.Fd())
	closeBeforeErr := before.Close()
	if idErr != nil || closeBeforeErr != nil {
		return errors.Join(fmt.Errorf("inspect UDF verification mountpoint: %w", idErr), closeBeforeErr)
	}

	command := exec.CommandContext(
		ctx,
		mountExecutable,
		"--internal-only",
		"--no-canonicalize",
		"--no-mtab",
		"-t", "udf",
		"-o", "ro,nosuid,nodev,noexec",
		"--",
		partitionPath,
		mountpoint,
	)
	command.Dir = "/"
	command.Env = []string{
		"HOME=/nonexistent",
		"LC_ALL=C.UTF-8",
		"LIBMOUNT_FSTAB=/dev/null",
		"LIBMOUNT_FORCE_MOUNT2=always",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("mount UDF read-only for verification: %w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	mounted = true
	cleanupMount := func() error {
		if !mounted {
			return nil
		}
		if err := syscall.Unmount(mountpoint, 0); err != nil {
			return fmt.Errorf("unmount verified UDF filesystem: %w", err)
		}
		mounted = false
		return nil
	}

	root, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Join(fmt.Errorf("open mounted UDF root: %w", err), cleanupMount())
	}
	rootMountID, mountIDErr := udfDescriptorMountID(root.Fd())
	if mountIDErr != nil {
		return errors.Join(mountIDErr, root.Close(), cleanupMount())
	}
	if rootMountID == beforeMountID {
		return errors.Join(errors.New("UDF mountpoint did not acquire a distinct mount identity"), root.Close(), cleanupMount())
	}
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(root.Fd()), &stat); err != nil {
		return errors.Join(fmt.Errorf("inspect mounted UDF filesystem: %w", err), root.Close(), cleanupMount())
	}
	if int64(stat.Type) != udfSuperMagic {
		return errors.Join(fmt.Errorf("mounted filesystem type %#x is not UDF", stat.Type), root.Close(), cleanupMount())
	}
	requiredFlags := udfStatReadOnly | udfStatNoSuid | udfStatNoDev | udfStatNoExec
	if uint64(stat.Flags)&requiredFlags != requiredFlags {
		return errors.Join(fmt.Errorf("mounted UDF flags %#x omit read-only,nosuid,nodev,noexec", stat.Flags), root.Close(), cleanupMount())
	}
	names, readErr := root.Readdirnames(1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(fmt.Errorf("read mounted UDF root: %w", readErr), root.Close(), cleanupMount())
	}
	if len(names) != 0 {
		return errors.Join(fmt.Errorf("fresh UDF root is not empty: first entry %q", names[0]), root.Close(), cleanupMount())
	}
	closeErr := root.Close()
	unmountErr := cleanupMount()
	return errors.Join(closeErr, unmountErr)
}

func openUDFVerificationRoot(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid UDF verification workspace root %q", path)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect UDF verification workspace root: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return nil, errors.New("UDF verification workspace root must be a real directory")
	}
	root, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open UDF verification workspace root: %w", err)
	}
	openInfo, err := root.Stat()
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect open UDF verification workspace root: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		root.Close()
		return nil, errors.New("UDF verification workspace root changed while opening")
	}
	stat, ok := openInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || openInfo.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, errors.New("UDF verification workspace root must be root-owned and not group/world writable")
	}
	return root, nil
}

func udfDescriptorMountID(fd uintptr) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, fmt.Errorf("read descriptor mount identity: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "mnt_id" {
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err != nil || id == 0 {
				return 0, fmt.Errorf("parse descriptor mount identity %q", value)
			}
			return id, nil
		}
	}
	return 0, errors.New("descriptor mount identity is unavailable")
}
