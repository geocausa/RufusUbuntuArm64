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

	casperConfigs := matchingFamilyConfigs(configs, FamilyUbuntuCasper)
	debianConfigs := matchingFamilyConfigs(configs, FamilyDebianLive)
	casper := casperKernel && casperInitrd && len(casperConfigs) > 0
	debian := liveKernel && liveInitrd && len(debianConfigs) > 0
	if casper && debian {
		return Detection{}, errors.New("media contains both casper and Debian live-boot layouts; persistence mode is ambiguous")
	}
	if casper {
		modernMetadata := hasRegular(root, "casper/install-sources.yaml")
		return detectUbuntu(info, casperConfigs, modernMetadata), nil
	}
	if debian {
		return detectDebian(info, debianConfigs), nil
	}
	if casperKernel && casperInitrd {
		return Detection{}, errors.New("ubuntu casper kernel and initrd were found, but no supported kernel command selects /casper/vmlinuz or boot=casper")
	}
	if liveKernel && liveInitrd {
		return Detection{}, errors.New("debian live kernel and initrd were found, but no supported kernel command contains boot=live")
	}
	return Detection{}, errors.New("media is not a supported Ubuntu casper or Debian live-boot layout")
}

func detectUbuntu(info string, configs map[string]string, modernMetadata bool) Detection {
	name := strings.TrimSpace(info)
	if name == "" {
		name = "Ubuntu casper"
	}
	detection := Detection{
		Family:          FamilyUbuntuCasper,
		DisplayName:     name,
		BootParameter:   "persistent",
		Filesystem:      "ext4",
		FilesystemLabel: "casper-rw",
		Evidence:        []string{"casper kernel/initrd", "casper kernel command"},
	}
	match := ubuntuVersionPattern.FindStringSubmatch(info)
	if len(match) == 3 {
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		detection.Version = match[1] + "." + match[2]
		detection.Evidence = append(detection.Evidence, ".disk/info Ubuntu release "+detection.Version)
		if major < minimumUbuntuMajor || (major == minimumUbuntuMajor && minor < minimumUbuntuMinor) {
			detection.FilesystemLabel = ""
			detection.Evidence = append(detection.Evidence, "Ubuntu releases older than 20.04 are outside the initial casper persistence compatibility scope")
			return detection
		}
	} else if modernMetadata {
		detection.Evidence = append(detection.Evidence, "casper/install-sources.yaml modern live-media metadata")
	} else {
		detection.FilesystemLabel = ""
		detection.Evidence = append(detection.Evidence, "could not establish Ubuntu 20.04+ compatibility from .disk/info or modern casper metadata")
		return detection
	}
	detection.PatchPaths, detection.AlreadyEnabledPaths = classifyConfigs(configs, detection.Family, detection.BootParameter)
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
	detection.PatchPaths, detection.AlreadyEnabledPaths = classifyConfigs(configs, detection.Family, detection.BootParameter)
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

func hasRegular(root fs.FS, name string) bool {
	file, err := root.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	return err == nil && info.Mode().IsRegular()
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

func matchingFamilyConfigs(configs map[string]string, family Family) map[string]string {
	matched := make(map[string]string)
	for name, content := range configs {
		familyLines, _, _ := inspectFamilyKernelLines(content, family, "")
		if familyLines > 0 {
			matched[name] = content
		}
	}
	return matched
}

func classifyConfigs(configs map[string]string, family Family, parameter string) (patch, enabled []string) {
	for name, content := range configs {
		familyLines, missing, present := inspectFamilyKernelLines(content, family, parameter)
		if familyLines == 0 {
			continue
		}
		if missing > 0 {
			patch = append(patch, name)
		} else if present > 0 {
			enabled = append(enabled, name)
		}
	}
	sort.Strings(patch)
	sort.Strings(enabled)
	return patch, enabled
}

func inspectFamilyKernelLines(content string, family Family, parameter string) (familyLines, missing, present int) {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !isKernelArgumentCommand(fields[0]) {
			continue
		}
		arguments := fields[1:]
		if !kernelArgumentsSelectFamily(arguments, family) {
			continue
		}
		familyLines++
		if parameter != "" && kernelArgumentsContain(arguments, parameter) {
			present++
		} else {
			missing++
		}
	}
	return familyLines, missing, present
}

func kernelArgumentsSelectFamily(arguments []string, family Family) bool {
	marker, ok := familyBootMarker(family)
	if !ok {
		return false
	}
	for _, raw := range arguments {
		if strings.HasPrefix(raw, "#") {
			break
		}
		token := normalizeKernelToken(raw)
		if kernelTokenMatches(token, marker) {
			return true
		}
		if family == FamilyUbuntuCasper && kernelPathMatchesFamily(token, family) {
			return true
		}
	}
	return false
}

func kernelArgumentsContain(arguments []string, expected string) bool {
	for _, raw := range arguments {
		if strings.HasPrefix(raw, "#") {
			break
		}
		if kernelTokenMatches(normalizeKernelToken(raw), expected) {
			return true
		}
	}
	return false
}

func familyBootMarker(family Family) (string, bool) {
	switch family {
	case FamilyUbuntuCasper:
		return "boot=casper", true
	case FamilyDebianLive:
		return "boot=live", true
	default:
		return "", false
	}
}

func normalizeKernelToken(token string) string {
	return strings.Trim(token, "\"' ,;[]()")
}

func kernelTokenMatches(token, expected string) bool {
	return token == expected || strings.HasPrefix(token, expected+"=")
}

func kernelPathMatchesFamily(token string, family Family) bool {
	lower := strings.ToLower(strings.ReplaceAll(token, "\\", "/"))
	directory := ""
	switch family {
	case FamilyUbuntuCasper:
		directory = "casper"
	case FamilyDebianLive:
		directory = "live"
	default:
		return false
	}
	marker := "/" + directory + "/"
	remainder := ""
	if index := strings.Index(lower, marker); index >= 0 {
		remainder = lower[index+len(marker):]
	} else if strings.HasPrefix(lower, directory+"/") {
		remainder = strings.TrimPrefix(lower, directory+"/")
	} else {
		return false
	}
	name := strings.SplitN(remainder, "/", 2)[0]
	return strings.HasPrefix(name, "vmlinuz")
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
