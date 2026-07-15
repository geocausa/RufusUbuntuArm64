//go:build linux

package safety

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/geocausa/rufus-linux-arm64/internal/device"
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
	return resolved, nil
}

func ValidateTarget(path string, dev device.BlockDevice, allowFixed bool) error {
	info, err := os.Stat(path)
	if err != nil { return fmt.Errorf("stat target: %w", err) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK { return ErrNotBlockDevice }
	if dev.Type != "disk" { return fmt.Errorf("refusing partition or non-disk target %s (lsblk type %q); select the whole disk", path, dev.Type) }
	if dev.ReadOnly { return fmt.Errorf("target %s is read-only", path) }
	if !allowFixed && !dev.Removable && dev.Transport != "usb" && dev.Transport != "mmc" { return fmt.Errorf("target %s is not marked removable or USB/MMC; use --allow-fixed only after checking the device carefully", path) }
	rootDisks, err := BackingDisksForPath("/")
	if err != nil { return fmt.Errorf("cannot safely identify the running root disk: %w", err) }
	if contains(rootDisks, filepath.Base(path)) { return fmt.Errorf("refusing to overwrite a disk that backs the running root filesystem: %s", path) }
	return nil
}

func BackingDisksForPath(path string) ([]string, error) {
	source, err := commandOutput("findmnt", "-n", "-o", "SOURCE", "--target", path)
	if err != nil { return nil, err }
	source = strings.TrimSpace(source)
	if bracket := strings.IndexByte(source, '['); bracket >= 0 { source = source[:bracket] }
	if source == "" || !strings.HasPrefix(source, "/dev/") { return nil, fmt.Errorf("%w: source=%q", ErrNotBlockBacked, source) }
	if resolved, err := filepath.EvalSymlinks(source); err == nil { source = resolved }
	output, err := commandOutput("lsblk", "-s", "-n", "-o", "NAME,TYPE", source)
	if err != nil { return nil, err }
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() { fields := strings.Fields(scanner.Text()); if len(fields) >= 2 && fields[len(fields)-1] == "disk" { seen[fields[0]] = struct{}{} } }
	if err := scanner.Err(); err != nil { return nil, fmt.Errorf("parse lsblk dependency output: %w", err) }
	if len(seen) == 0 { return nil, fmt.Errorf("lsblk found no top-level disk backing %s", source) }
	disks := make([]string, 0, len(seen)); for name := range seen { disks = append(disks, name) }; sort.Strings(disks); return disks, nil
}

func EnsureImageNotOnTarget(imagePath, targetPath string) error {
	imageDisks, err := BackingDisksForPath(imagePath)
	if err != nil { if errors.Is(err, ErrNotBlockBacked) { return nil }; return fmt.Errorf("cannot identify the image file's backing disk: %w", err) }
	if contains(imageDisks, filepath.Base(targetPath)) { return fmt.Errorf("image file is stored on the target disk %s; move the image to another disk before writing", targetPath) }
	return nil
}

func UnmountDescendants(dev device.BlockDevice) error {
	mounted := device.MountedDescendants(dev)
	for i := len(mounted)-1; i >= 0; i-- { node := mounted[i]; for j := len(node.Mountpoints)-1; j >= 0; j-- { mountpoint := node.Mountpoints[j]; cmd := exec.Command("umount", "--", mountpoint); var stderr bytes.Buffer; cmd.Stderr = &stderr; if err := cmd.Run(); err != nil { return fmt.Errorf("unmount %s (%s): %w: %s", node.Path, mountpoint, err, strings.TrimSpace(stderr.String())) } } }
	return nil
}

func RequireRoot() error { if os.Geteuid() != 0 { return errors.New("raw disk writing requires root; rerun with sudo") }; return nil }
func RereadPartitionTable(path string) error { cmd := exec.Command("blockdev", "--rereadpt", path); var stderr bytes.Buffer; cmd.Stderr = &stderr; if err := cmd.Run(); err != nil { return fmt.Errorf("blockdev --rereadpt: %w: %s", err, strings.TrimSpace(stderr.String())) }; return nil }
func commandOutput(name string, args ...string) (string, error) { cmd:=exec.Command(name,args...); var stdout,stderr bytes.Buffer; cmd.Stdout=&stdout; cmd.Stderr=&stderr; if err:=cmd.Run();err!=nil{return "",fmt.Errorf("%s: %w: %s",name,err,strings.TrimSpace(stderr.String()))}; return stdout.String(),nil }
func contains(items []string,target string) bool { for _,item:=range items { if item==target{return true} }; return false }
