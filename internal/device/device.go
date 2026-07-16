package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BlockDevice is a normalized subset of lsblk's JSON output. Identity is a
// deterministic fingerprint of the kernel device metadata that the GUI passes
// back to the privileged helper. It is not an authentication token; it is a
// fail-closed guard against /dev/sdX being reassigned between selection and use.
type BlockDevice struct {
	Name         string        `json:"name"`
	Path         string        `json:"path"`
	Type         string        `json:"type"`
	Size         uint64        `json:"size"`
	Model        string        `json:"model"`
	Vendor       string        `json:"vendor"`
	Transport    string        `json:"tran"`
	Removable    bool          `json:"removable"`
	ReadOnly     bool          `json:"read_only"`
	Hotplug      bool          `json:"hotplug"`
	ParentName   string        `json:"pkname"`
	MajorMinor   string        `json:"major_minor"`
	Serial       string        `json:"serial"`
	WWN          string        `json:"wwn"`
	DiskSequence string        `json:"disk_sequence"`
	Identity     string        `json:"identity"`
	Mountpoints  []string      `json:"mountpoints"`
	Children     []BlockDevice `json:"children,omitempty"`
}

type rawDevice struct {
	Name        string      `json:"name"`
	Path        string      `json:"path"`
	Type        string      `json:"type"`
	Size        any         `json:"size"`
	Model       string      `json:"model"`
	Vendor      string      `json:"vendor"`
	Transport   string      `json:"tran"`
	Removable   any         `json:"rm"`
	ReadOnly    any         `json:"ro"`
	Hotplug     any         `json:"hotplug"`
	ParentName  string      `json:"pkname"`
	MajorMinor  string      `json:"maj:min"`
	Serial      string      `json:"serial"`
	WWN         string      `json:"wwn"`
	Mountpoints any         `json:"mountpoints"`
	Children    []rawDevice `json:"children,omitempty"`
}

type rawList struct {
	BlockDevices []rawDevice `json:"blockdevices"`
}

var sysClassBlockRoot = "/sys/class/block"

func List() ([]BlockDevice, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx,
		"lsblk", "--json", "--bytes", "--output",
		"NAME,PATH,TYPE,SIZE,MODEL,VENDOR,TRAN,RM,RO,HOTPLUG,MOUNTPOINTS,PKNAME,MAJ:MIN,SERIAL,WWN",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("run lsblk: %w", ctx.Err())
		}
		return nil, fmt.Errorf("run lsblk: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var raw rawList
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("parse lsblk JSON: %w", err)
	}

	out := make([]BlockDevice, 0, len(raw.BlockDevices))
	for _, item := range raw.BlockDevices {
		converted, err := convert(item)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func Find(path string) (BlockDevice, error) {
	devices, err := List()
	if err != nil {
		return BlockDevice{}, err
	}
	for _, dev := range devices {
		if found, ok := findRecursive(dev, path); ok {
			return found, nil
		}
	}
	return BlockDevice{}, fmt.Errorf("device %q was not reported by lsblk", path)
}

func WholeDisks(devices []BlockDevice) []BlockDevice {
	out := make([]BlockDevice, 0)
	for _, dev := range devices {
		if dev.Type == "disk" {
			out = append(out, dev)
		}
	}
	return out
}

func Flatten(dev BlockDevice) []BlockDevice {
	out := []BlockDevice{dev}
	for _, child := range dev.Children {
		out = append(out, Flatten(child)...)
	}
	return out
}

func MountedDescendants(dev BlockDevice) []BlockDevice {
	var out []BlockDevice
	for _, node := range Flatten(dev) {
		if len(node.Mountpoints) > 0 {
			out = append(out, node)
		}
	}
	return out
}

// IsNormalRemovableTarget is deliberately conservative. USB-attached disks are
// accepted because many USB enclosures report RM=0. MMC is accepted only when
// the kernel explicitly marks it removable, avoiding internal eMMC exposure.
func IsNormalRemovableTarget(dev BlockDevice) bool {
	return dev.Removable || dev.Transport == "usb"
}

// IdentityToken returns a stable representation of the exact lsblk snapshot.
// MAJ:MIN intentionally participates so a disconnect/reconnect or path reuse
// causes the privileged operation to fail rather than guessing.
func IdentityToken(dev BlockDevice) string {
	fields := []string{
		dev.Path,
		dev.Type,
		strconv.FormatUint(dev.Size, 10),
		dev.MajorMinor,
		dev.Serial,
		dev.WWN,
		dev.DiskSequence,
		dev.Vendor,
		dev.Model,
		dev.Transport,
		strconv.FormatBool(dev.Removable),
		strconv.FormatBool(dev.ReadOnly),
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:])
}

func findRecursive(dev BlockDevice, path string) (BlockDevice, bool) {
	if dev.Path == path {
		return dev, true
	}
	for _, child := range dev.Children {
		if found, ok := findRecursive(child, path); ok {
			return found, true
		}
	}
	return BlockDevice{}, false
}

func convert(in rawDevice) (BlockDevice, error) {
	size, err := parseUint(in.Size)
	if err != nil {
		return BlockDevice{}, fmt.Errorf("parse size for %s: %w", in.Path, err)
	}
	removable, err := parseBool(in.Removable)
	if err != nil {
		return BlockDevice{}, fmt.Errorf("parse removable flag for %s: %w", in.Path, err)
	}
	readOnly, err := parseBool(in.ReadOnly)
	if err != nil {
		return BlockDevice{}, fmt.Errorf("parse read-only flag for %s: %w", in.Path, err)
	}
	hotplug, err := parseBool(in.Hotplug)
	if err != nil {
		return BlockDevice{}, fmt.Errorf("parse hotplug flag for %s: %w", in.Path, err)
	}
	mounts, err := parseMountpoints(in.Mountpoints)
	if err != nil {
		return BlockDevice{}, fmt.Errorf("parse mountpoints for %s: %w", in.Path, err)
	}

	out := BlockDevice{
		Name:         strings.TrimSpace(in.Name),
		Path:         strings.TrimSpace(in.Path),
		Type:         strings.TrimSpace(in.Type),
		Size:         size,
		Model:        strings.TrimSpace(in.Model),
		Vendor:       strings.TrimSpace(in.Vendor),
		Transport:    strings.ToLower(strings.TrimSpace(in.Transport)),
		Removable:    removable,
		ReadOnly:     readOnly,
		Hotplug:      hotplug,
		ParentName:   strings.TrimSpace(in.ParentName),
		MajorMinor:   strings.TrimSpace(in.MajorMinor),
		Serial:       strings.TrimSpace(in.Serial),
		WWN:          strings.TrimSpace(in.WWN),
		DiskSequence: readDiskSequence(strings.TrimSpace(in.Name)),
		Mountpoints:  mounts,
	}
	out.Identity = IdentityToken(out)
	for _, child := range in.Children {
		converted, err := convert(child)
		if err != nil {
			return BlockDevice{}, err
		}
		out.Children = append(out.Children, converted)
	}
	return out, nil
}

func readDiskSequence(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(sysClassBlockRoot, name, "diskseq"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func parseUint(v any) (uint64, error) {
	switch x := v.(type) {
	case float64:
		if x < 0 {
			return 0, errors.New("negative number")
		}
		return uint64(x), nil
	case string:
		if x == "" {
			return 0, nil
		}
		return strconv.ParseUint(x, 10, 64)
	case nil:
		return 0, nil
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}

func parseBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case float64:
		return x != 0, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes":
			return true, nil
		case "0", "false", "no", "":
			return false, nil
		default:
			return false, fmt.Errorf("unexpected value %q", x)
		}
	case nil:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected type %T", v)
	}
}

func parseMountpoints(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	var out []string
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if item == nil {
				continue
			}
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected mountpoint type %T", item)
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
	case string:
		for _, mountpoint := range strings.Split(x, "\n") {
			mountpoint = strings.TrimSpace(mountpoint)
			if mountpoint != "" {
				out = append(out, mountpoint)
			}
		}
	default:
		return nil, fmt.Errorf("unexpected type %T", v)
	}
	return out, nil
}
