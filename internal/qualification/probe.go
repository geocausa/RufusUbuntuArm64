//go:build linux

package qualification

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type ProbePaths struct {
	BootID        string
	Cmdline       string
	MountInfo     string
	OSRelease     string
	KernelRelease string
	UEFIRoot      string
}

type ProbeOptions struct {
	StateDirectory string
	Paths          ProbePaths
	Now            func() time.Time
	Random         io.Reader
}

type Evidence struct {
	Schema                   int       `json:"schema"`
	Phase                    string    `json:"phase"`
	GeneratedAt              time.Time `json:"generated_at"`
	CreationRecordSHA256     string    `json:"creation_record_sha256"`
	Creator                  string    `json:"creator"`
	MediaDisplayName         string    `json:"media_display_name"`
	MediaFamily              string    `json:"media_family"`
	MediaArchitecture        string    `json:"media_architecture"`
	RuntimeArchitecture      string    `json:"runtime_architecture"`
	UEFIBooted               bool      `json:"uefi_booted"`
	FamilyBootParameter      bool      `json:"family_boot_parameter"`
	PersistenceParameter     bool      `json:"persistence_parameter"`
	RootFilesystem           string    `json:"root_filesystem"`
	RootOverlay              bool      `json:"root_overlay"`
	KernelRelease            string    `json:"kernel_release"`
	OSPrettyName             string    `json:"os_pretty_name"`
	InitialBootIDSHA256      string    `json:"initial_boot_id_sha256"`
	CurrentBootIDSHA256      string    `json:"current_boot_id_sha256"`
	BootIDChanged            bool      `json:"boot_id_changed"`
	MarkerTokenSHA256        string    `json:"marker_token_sha256"`
	RebootSurvivalConfirmed  bool      `json:"reboot_survival_confirmed"`
	ExpectedPersistenceLabel string    `json:"expected_persistence_label"`
}

type marker struct {
	Schema               int       `json:"schema"`
	CreationRecordSHA256 string    `json:"creation_record_sha256"`
	BootID               string    `json:"boot_id"`
	Token                string    `json:"token"`
	CreatedAt            time.Time `json:"created_at"`
}

func DefaultProbePaths() ProbePaths {
	return ProbePaths{
		BootID:        "/proc/sys/kernel/random/boot_id",
		Cmdline:       "/proc/cmdline",
		MountInfo:     "/proc/self/mountinfo",
		OSRelease:     "/etc/os-release",
		KernelRelease: "/proc/sys/kernel/osrelease",
		UEFIRoot:      "/sys/firmware/efi",
	}
}

func Start(recordPath string, options ProbeOptions) (Evidence, error) {
	stored, environment, bootID, err := inspectEnvironment(recordPath, options)
	if err != nil {
		return Evidence{}, err
	}
	if err := validateLiveEnvironment(stored.Record, environment); err != nil {
		return Evidence{}, err
	}
	stateDir, err := prepareStateDirectory(options.StateDirectory)
	if err != nil {
		return Evidence{}, err
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, tokenBytes); err != nil {
		return Evidence{}, fmt.Errorf("generate qualification marker: %w", err)
	}
	now := currentTime(options)
	value := marker{
		Schema:               EvidenceSchema,
		CreationRecordSHA256: stored.SHA256,
		BootID:               bootID,
		Token:                hex.EncodeToString(tokenBytes),
		CreatedAt:            now,
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return Evidence{}, err
	}
	data = append(data, '\n')
	markerPath := filepath.Join(stateDir, stored.SHA256+".json")
	if err := writeAtomicNoFollow(markerPath, data, 0o600); err != nil {
		return Evidence{}, fmt.Errorf("write qualification marker: %w", err)
	}
	return buildEvidence("initial", stored, environment, bootID, bootID, value.Token, now, false), nil
}

func Verify(recordPath string, options ProbeOptions) (Evidence, error) {
	stored, environment, bootID, err := inspectEnvironment(recordPath, options)
	if err != nil {
		return Evidence{}, err
	}
	if err := validateLiveEnvironment(stored.Record, environment); err != nil {
		return Evidence{}, err
	}
	stateDir, err := prepareStateDirectory(options.StateDirectory)
	if err != nil {
		return Evidence{}, err
	}
	markerPath := filepath.Join(stateDir, stored.SHA256+".json")
	data, err := readRegularNoFollow(markerPath, 64*1024)
	if err != nil {
		return Evidence{}, fmt.Errorf("read qualification marker: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value marker
	if err := decoder.Decode(&value); err != nil {
		return Evidence{}, fmt.Errorf("decode qualification marker: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Evidence{}, err
	}
	if value.Schema != EvidenceSchema || value.CreationRecordSHA256 != stored.SHA256 || len(value.BootID) < 16 || len(value.Token) != 64 {
		return Evidence{}, errors.New("qualification marker does not match the creation record")
	}
	if _, err := hex.DecodeString(value.Token); err != nil {
		return Evidence{}, errors.New("qualification marker token is invalid")
	}
	if value.BootID == bootID {
		return Evidence{}, errors.New("qualification verification requires a reboot after the marker was created")
	}
	now := currentTime(options)
	return buildEvidence("verified", stored, environment, value.BootID, bootID, value.Token, now, true), nil
}

func WriteEvidence(path string, evidence Evidence) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("qualification report output path is required")
	}
	evidence.Schema = EvidenceSchema
	evidence.GeneratedAt = evidence.GeneratedAt.UTC().Truncate(time.Second)
	if evidence.Phase != "initial" && evidence.Phase != "verified" {
		return "", errors.New("qualification report phase is invalid")
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := realDirectory(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("qualification report directory: %w", err)
	}
	absolute = filepath.Join(parent, filepath.Base(absolute))
	if err := writeAtomicNoFollow(absolute, data, 0o600); err != nil {
		return "", err
	}
	checksum := []byte(fmt.Sprintf("%s  %s\n", hash, filepath.Base(absolute)))
	if err := writeAtomicNoFollow(absolute+".sha256", checksum, 0o600); err != nil {
		return "", err
	}
	return hash, nil
}

type environmentEvidence struct {
	architecture         string
	uefi                 bool
	familyParameter      bool
	persistenceParameter bool
	rootFilesystem       string
	rootOverlay          bool
	kernelRelease        string
	osPrettyName         string
}

func inspectEnvironment(recordPath string, options ProbeOptions) (StoredRecord, environmentEvidence, string, error) {
	stored, err := LoadVerifiedRecord(recordPath)
	if err != nil {
		return StoredRecord{}, environmentEvidence{}, "", err
	}
	paths := options.Paths
	defaults := DefaultProbePaths()
	if paths.BootID == "" {
		paths.BootID = defaults.BootID
	}
	if paths.Cmdline == "" {
		paths.Cmdline = defaults.Cmdline
	}
	if paths.MountInfo == "" {
		paths.MountInfo = defaults.MountInfo
	}
	if paths.OSRelease == "" {
		paths.OSRelease = defaults.OSRelease
	}
	if paths.KernelRelease == "" {
		paths.KernelRelease = defaults.KernelRelease
	}
	if paths.UEFIRoot == "" {
		paths.UEFIRoot = defaults.UEFIRoot
	}
	bootID, err := readTrimmed(paths.BootID, 4096)
	if err != nil || len(bootID) < 16 {
		return stored, environmentEvidence{}, "", errors.New("could not read a valid Linux boot ID")
	}
	cmdline, err := readTrimmed(paths.Cmdline, 1024*1024)
	if err != nil {
		return stored, environmentEvidence{}, "", fmt.Errorf("read kernel command line: %w", err)
	}
	familyParameter, persistenceParameter := relevantParameters(cmdline, stored.Record.Family, stored.Record.BootParameter)
	rootFilesystem, err := rootFilesystem(paths.MountInfo)
	if err != nil {
		return stored, environmentEvidence{}, "", err
	}
	kernel, _ := readTrimmed(paths.KernelRelease, 4096)
	osName := readOSPrettyName(paths.OSRelease)
	uefiInfo, uefiErr := os.Stat(paths.UEFIRoot)
	uefi := uefiErr == nil && uefiInfo.IsDir()
	environment := environmentEvidence{
		architecture:         normalizeArchitecture(runtime.GOARCH),
		uefi:                 uefi,
		familyParameter:      familyParameter,
		persistenceParameter: persistenceParameter,
		rootFilesystem:       rootFilesystem,
		rootOverlay:          rootFilesystem == "overlay" || rootFilesystem == "overlayfs" || rootFilesystem == "aufs",
		kernelRelease:        kernel,
		osPrettyName:         osName,
	}
	return stored, environment, bootID, nil
}

func validateLiveEnvironment(record CreationRecord, environment environmentEvidence) error {
	if normalizeArchitecture(record.Architecture) != environment.architecture {
		return fmt.Errorf("runtime architecture %s does not match created media architecture %s", environment.architecture, record.Architecture)
	}
	if !environment.uefi {
		return errors.New("the live system was not booted through UEFI")
	}
	if !environment.familyParameter {
		return errors.New("the expected live-media boot parameter is absent")
	}
	if !environment.persistenceParameter {
		return errors.New("the persistence kernel parameter is absent")
	}
	if !environment.rootOverlay {
		return fmt.Errorf("the live root filesystem is %q rather than an overlay", environment.rootFilesystem)
	}
	return nil
}

func buildEvidence(phase string, stored StoredRecord, environment environmentEvidence, initialBootID, currentBootID, token string, now time.Time, survived bool) Evidence {
	return Evidence{
		Schema:                   EvidenceSchema,
		Phase:                    phase,
		GeneratedAt:              now,
		CreationRecordSHA256:     stored.SHA256,
		Creator:                  stored.Record.Creator,
		MediaDisplayName:         stored.Record.DisplayName,
		MediaFamily:              stored.Record.Family,
		MediaArchitecture:        stored.Record.Architecture,
		RuntimeArchitecture:      environment.architecture,
		UEFIBooted:               environment.uefi,
		FamilyBootParameter:      environment.familyParameter,
		PersistenceParameter:     environment.persistenceParameter,
		RootFilesystem:           environment.rootFilesystem,
		RootOverlay:              environment.rootOverlay,
		KernelRelease:            environment.kernelRelease,
		OSPrettyName:             environment.osPrettyName,
		InitialBootIDSHA256:      stringHash(initialBootID),
		CurrentBootIDSHA256:      stringHash(currentBootID),
		BootIDChanged:            initialBootID != currentBootID,
		MarkerTokenSHA256:        stringHash(token),
		RebootSurvivalConfirmed:  survived,
		ExpectedPersistenceLabel: stored.Record.Persistence.Label,
	}
}

func prepareStateDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/rufusarm64/qualification"
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", errors.New("qualification state directory must not contain symbolic links")
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("qualification state directory must be a real directory")
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return "", err
	}
	return absolute, nil
}

func relevantParameters(cmdline, family, expected string) (bool, bool) {
	family = strings.ToLower(strings.TrimSpace(family))
	expected = strings.ToLower(strings.TrimSpace(expected))
	familyMatch := false
	persistenceMatch := false
	for _, field := range strings.Fields(cmdline) {
		lower := strings.ToLower(field)
		if (family == "ubuntu-casper" && lower == "boot=casper") || (family == "debian-live" && lower == "boot=live") {
			familyMatch = true
		}
		name := lower
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
		}
		if name == expected || (expected == "persistent" && name == "persistent") || (expected == "persistence" && name == "persistence") {
			persistenceMatch = true
		}
	}
	return familyMatch, persistenceMatch
}

func rootFilesystem(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read mount information: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[4] != "/" {
			continue
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) {
			return "", errors.New("root mount information is malformed")
		}
		return fields[separator+1], nil
	}
	return "", errors.New("root mount was not found")
}

func readOSPrettyName(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1024*1024 {
		return ""
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		values[strings.TrimSpace(key)] = value
	}
	if value := values["PRETTY_NAME"]; value != "" {
		return value
	}
	return strings.TrimSpace(values["NAME"] + " " + values["VERSION"])
}

func readTrimmed(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", errors.New("input exceeds the qualification size limit")
	}
	return strings.TrimSpace(string(data)), nil
}

func normalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "amd64"
	case "i386", "i686", "386", "x86":
		return "386"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func currentTime(options ProbeOptions) time.Time {
	if options.Now != nil {
		return options.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func stringHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func SortedEvidenceChecks(evidence Evidence) []string {
	checks := []string{
		fmt.Sprintf("architecture=%t", evidence.MediaArchitecture == evidence.RuntimeArchitecture),
		fmt.Sprintf("uefi=%t", evidence.UEFIBooted),
		fmt.Sprintf("family-parameter=%t", evidence.FamilyBootParameter),
		fmt.Sprintf("persistence-parameter=%t", evidence.PersistenceParameter),
		fmt.Sprintf("root-overlay=%t", evidence.RootOverlay),
		fmt.Sprintf("reboot-survived=%t", evidence.RebootSurvivalConfirmed),
	}
	sort.Strings(checks)
	return checks
}
