package persistence

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Family identifies the live-boot implementation that consumes a persistence
// partition. Detection is deliberately limited to layouts whose upstream boot
// parameters and persistence-volume contracts are well understood.
type Family string

const (
	FamilyUbuntuCasper Family = "ubuntu-casper"
	FamilyDebianLive   Family = "debian-live"
)

const (
	maxInfoBytes       = 16 * 1024
	maxConfigBytes     = 1024 * 1024
	maxLoaderEntries   = 64
	minimumUbuntuMajor = 20
	minimumUbuntuMinor = 4
)

var ubuntuVersionPattern = regexp.MustCompile(`(?i)(?:ubuntu|kubuntu|xubuntu|lubuntu|ubuntu\s+(?:mate|budgie|studio|unity|cinnamon|kylin))[^0-9]{0,48}([0-9]{2})\.([0-9]{2})`)

var fixedConfigPaths = []string{
	"boot/grub/grub.cfg",
	"boot/grub/loopback.cfg",
	"isolinux/isolinux.cfg",
	"isolinux/txt.cfg",
	"isolinux/live.cfg",
	"syslinux.cfg",
	"EFI/BOOT/grub.cfg",
	"efi/boot/grub.cfg",
}

// Detection describes the persistence contract and the boot configurations
// that would require a parameter edit. It does not modify the supplied media.
type Detection struct {
	Family              Family   `json:"family"`
	DisplayName         string   `json:"display_name"`
	Version             string   `json:"version,omitempty"`
	BootParameter       string   `json:"boot_parameter"`
	Filesystem          string   `json:"filesystem"`
	FilesystemLabel     string   `json:"filesystem_label"`
	PersistenceConfig   string   `json:"persistence_config,omitempty"`
	PatchPaths          []string `json:"patch_paths,omitempty"`
	AlreadyEnabledPaths []string `json:"already_enabled_paths,omitempty"`
	Evidence            []string `json:"evidence"`
}

// Detect inspects a mounted or extracted live-media tree through fs.FS. Only a
// bounded set of expected marker and boot-configuration paths is read.
func Detect(root fs.FS) (Detection, error) {
	if root == nil {
		return Detection{}, errors.New("media filesystem is nil")
	}
	info, _ := readSmallRegular(root, ".disk/info", maxInfoBytes)
	configs, err := readBootConfigs(root)
	if err != nil {
		return Detection{}, err
	}

	casperKernel := hasPrefixedRegular(root, "casper", "vmlinuz")
	casperInitrd := hasPrefixedRegular(root, "casper", "initrd")
	liveKernel := hasPrefixedRegular(root, "live", "vmlinuz")
	liveInitrd := hasPrefixedRegular(root, "live", "initrd")

	casperConfigs := matchingConfigs(configs, "boot=casper")
	debianConfigs := matchingConfigs(configs, "boot=live")
	casper := casperKernel && casperInitrd && len(casperConfigs) > 0
	debian := liveKernel && liveInitrd && len(debianConfigs) > 0
	if casper && debian {
		return Detection{}, errors.New("media contains both casper and Debian live-boot layouts; persistence mode is ambiguous")
	}
	if casper {
		return detectUbuntu(info, casperConfigs), nil
	}
	if debian {
		return detectDebian(info, debianConfigs), nil
	}
	return Detection{}, errors.New("media is not a supported Ubuntu casper or Debian live-boot layout")
}

func detectUbuntu(info string, configs map[string]string) Detection {
	match := ubuntuVersionPattern.FindStringSubmatch(info)
	if len(match) != 3 {
		return Detection{Family: FamilyUbuntuCasper, DisplayName: "Ubuntu casper", Evidence: []string{"casper kernel/initrd and boot=casper configuration"}}
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	version := match[1] + "." + match[2]
	detection := Detection{
		Family:          FamilyUbuntuCasper,
		DisplayName:     strings.TrimSpace(info),
		Version:         version,
		BootParameter:   "persistent",
		Filesystem:      "ext4",
		FilesystemLabel: "casper-rw",
		Evidence:        []string{"casper kernel/initrd", "boot=casper configuration", ".disk/info Ubuntu release " + version},
	}
	if major < minimumUbuntuMajor || (major == minimumUbuntuMajor && minor < minimumUbuntuMinor) {
		detection.FilesystemLabel = ""
		detection.Evidence = append(detection.Evidence, "Ubuntu releases older than 20.04 are outside the initial casper persistence compatibility scope")
		return detection
	}
	detection.PatchPaths, detection.AlreadyEnabledPaths = classifyConfigs(configs, detection.BootParameter)
	return detection
}

func detectDebian(info string, configs map[string]string) Detection {
	name := strings.TrimSpace(info)
	if name == "" {
		name = "Debian live-boot"
	}
	detection := Detection{
		Family:            FamilyDebianLive,
		DisplayName:       name,
		BootParameter:     "persistence",
		Filesystem:        "ext4",
		FilesystemLabel:   "persistence",
		PersistenceConfig: "/ union\n",
		Evidence:          []string{"live kernel/initrd", "boot=live configuration"},
	}
	detection.PatchPaths, detection.AlreadyEnabledPaths = classifyConfigs(configs, detection.BootParameter)
	return detection
}

// Ready reports whether the detected media has a complete, supported
// persistence contract and at least one boot configuration that can use it.
func (d Detection) Ready() bool {
	return d.Family != "" && d.Filesystem == "ext4" && d.FilesystemLabel != "" &&
		(len(d.PatchPaths) > 0 || len(d.AlreadyEnabledPaths) > 0)
}

func readBootConfigs(root fs.FS) (map[string]string, error) {
	paths := append([]string(nil), fixedConfigPaths...)
	for _, directory := range []string{"loader/entries", "boot/loader/entries"} {
		entries, err := fs.ReadDir(root, directory)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", directory, err)
		}
		if len(entries) > maxLoaderEntries {
			return nil, fmt.Errorf("%s contains too many boot entries", directory)
		}
		for _, entry := range entries {
			if entry.Type().IsRegular() && strings.HasSuffix(strings.ToLower(entry.Name()), ".conf") {
				paths = append(paths, path.Join(directory, entry.Name()))
			}
		}
	}

	configs := make(map[string]string)
	for _, configPath := range paths {
		content, err := readSmallRegular(root, configPath, maxConfigBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read boot configuration %s: %w", configPath, err)
		}
		configs[configPath] = content
	}
	return configs, nil
}

func readSmallRegular(root fs.FS, name string, limit int64) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() < 0 || info.Size() > limit {
		return "", fmt.Errorf("%s exceeds the %d-byte inspection limit", name, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%s exceeds the %d-byte inspection limit", name, limit)
	}
	return string(data), nil
}

func hasPrefixedRegular(root fs.FS, directory, prefix string) bool {
	entries, err := fs.ReadDir(root, directory)
	if err != nil || len(entries) > 128 {
		return false
	}
	prefix = strings.ToLower(prefix)
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(strings.ToLower(entry.Name()), prefix) {
			return true
		}
	}
	return false
}

func matchingConfigs(configs map[string]string, bootMarker string) map[string]string {
	matched := make(map[string]string)
	for name, content := range configs {
		if containsKernelToken(content, bootMarker) {
			matched[name] = content
		}
	}
	return matched
}

func classifyConfigs(configs map[string]string, parameter string) (patch, enabled []string) {
	for name, content := range configs {
		if containsKernelToken(content, parameter) {
			enabled = append(enabled, name)
		} else {
			patch = append(patch, name)
		}
	}
	sort.Strings(patch)
	sort.Strings(enabled)
	return patch, enabled
}

func containsKernelToken(content, token string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !isKernelArgumentCommand(fields[0]) {
			continue
		}
		for _, field := range fields[1:] {
			field = strings.Trim(field, "\"' ,;[]()")
			if field == token || strings.HasPrefix(field, token+"=") {
				return true
			}
		}
	}
	return false
}

func isKernelArgumentCommand(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	switch command {
	case "linux", "linuxefi", "linux16", "append", "options", "kernel":
		return true
	default:
		return false
	}
}
