//go:build linux

package acquisition

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	UpdateStateSchema   = 1
	MaxUpdateStateBytes = 64 * 1024
)

// UpdateState records the highest authenticated release metadata and root
// accepted by this user. The package bytes remain independently hash-verified.
type UpdateState struct {
	Schema                 int    `json:"schema"`
	RootVersion            int    `json:"root_version"`
	RootSHA256             string `json:"root_sha256"`
	ReleaseMetadataVersion int    `json:"release_metadata_version"`
	ReleaseMetadataSHA256  string `json:"release_metadata_sha256"`
	ReleaseVersion         string `json:"release_version"`
	AcceptedAt             string `json:"accepted_at"`
}

// UpdateStateOptions controls rollback-state admission and publication.
type UpdateStateOptions struct {
	Path                   string
	MinimumMetadataVersion int
	Now                    time.Time
}

// UpdateStateResult combines the authenticated update decision with its
// durably accepted owner-only rollback state.
type UpdateStateResult struct {
	Decision  UpdateDecision `json:"decision"`
	State     UpdateState    `json:"state"`
	StatePath string         `json:"state_path"`
}

// ResolveUpdateStatePath returns the explicit path or the XDG-compatible
// per-user state location used by update verification and download.
func ResolveUpdateStatePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
		if base != "" && !filepath.IsAbs(base) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("resolve user home for update state: %w", err)
			}
			base = filepath.Join(home, ".local", "state")
		}
		value = filepath.Join(base, "rufusarm64", "update", "state.json")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve update state path: %w", err)
	}
	return absolute, nil
}

// AcceptReleaseMetadata verifies rollback and clock invariants under an
// owner-only exclusive lock, then atomically publishes the highest accepted
// root/release state. It does not download or install software.
func AcceptReleaseMetadata(root *VerifiedRoot, release *VerifiedRelease, currentVersion string, options UpdateStateOptions) (UpdateStateResult, error) {
	rootSnapshot, err := root.trustSnapshot()
	if err != nil {
		return UpdateStateResult{}, err
	}
	releaseSnapshot, err := release.trustSnapshot()
	if err != nil {
		return UpdateStateResult{}, err
	}
	if releaseSnapshot.rootVersion != rootSnapshot.metadata.Version || releaseSnapshot.rootSHA256 != rootSnapshot.sha256 {
		return UpdateStateResult{}, errors.New("authenticated release metadata is bound to a different trusted root")
	}
	if options.MinimumMetadataVersion < 0 {
		return UpdateStateResult{}, errors.New("minimum metadata version cannot be negative")
	}
	statePath, err := ResolveUpdateStatePath(options.Path)
	if err != nil {
		return UpdateStateResult{}, err
	}
	directory := filepath.Dir(statePath)
	if err := ensurePrivateDirectory(directory); err != nil {
		return UpdateStateResult{}, fmt.Errorf("secure update state directory: %w", err)
	}
	lock, err := lockUpdateState(statePath + ".lock")
	if err != nil {
		return UpdateStateResult{}, err
	}
	defer unlockUpdateState(lock)

	previous, exists, err := loadUpdateState(statePath)
	if err != nil {
		return UpdateStateResult{}, err
	}
	now := normalizedChannelNow(options.Now)
	if err := enforceUpdateStateClock(previous, exists, now); err != nil {
		return UpdateStateResult{}, err
	}
	if err := enforceUpdateStateRollback(previous, exists, rootSnapshot, releaseSnapshot); err != nil {
		return UpdateStateResult{}, err
	}
	minimum := options.MinimumMetadataVersion
	if exists && previous.ReleaseMetadataVersion > minimum {
		minimum = previous.ReleaseMetadataVersion
	}
	decision, err := EvaluateRelease(currentVersion, minimum, release)
	if err != nil {
		return UpdateStateResult{}, err
	}
	acceptedAt := now
	if exists {
		previousTime, err := time.Parse(time.RFC3339, previous.AcceptedAt)
		if err != nil {
			return UpdateStateResult{}, err
		}
		if previousTime.After(acceptedAt) {
			acceptedAt = previousTime
		}
	}
	state := UpdateState{
		Schema:                 UpdateStateSchema,
		RootVersion:            rootSnapshot.metadata.Version,
		RootSHA256:             rootSnapshot.sha256,
		ReleaseMetadataVersion: releaseSnapshot.metadata.Version,
		ReleaseMetadataSHA256:  releaseSnapshot.sha256,
		ReleaseVersion:         releaseSnapshot.metadata.ReleaseVersion,
		AcceptedAt:             acceptedAt.UTC().Format(time.RFC3339),
	}
	if err := storeUpdateState(statePath, state); err != nil {
		return UpdateStateResult{}, err
	}
	decision.StatePath = statePath
	decision.AcceptedAt = state.AcceptedAt
	decision.RootVersion = state.RootVersion
	decision.RootSHA256 = state.RootSHA256
	return UpdateStateResult{Decision: decision, State: state, StatePath: statePath}, nil
}

func loadUpdateState(path string) (UpdateState, bool, error) {
	file, err := openPrivateUpdateState(path)
	if errors.Is(err, os.ErrNotExist) {
		return UpdateState{}, false, nil
	}
	if err != nil {
		return UpdateState{}, false, fmt.Errorf("read update rollback state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return UpdateState{}, false, err
	}
	if info.Size() < 1 || info.Size() > MaxUpdateStateBytes {
		return UpdateState{}, false, fmt.Errorf("update rollback state must be between 1 and %d bytes", MaxUpdateStateBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxUpdateStateBytes+1))
	if err != nil {
		return UpdateState{}, false, err
	}
	after, err := file.Stat()
	if err != nil {
		return UpdateState{}, false, err
	}
	if !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() {
		return UpdateState{}, false, errors.New("update rollback state changed while it was being read")
	}
	if len(data) > MaxUpdateStateBytes {
		return UpdateState{}, false, fmt.Errorf("update rollback state exceeds %d bytes", MaxUpdateStateBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return UpdateState{}, false, err
	}
	var state UpdateState
	if err := decodeStrictJSON(data, &state, "update rollback state"); err != nil {
		return UpdateState{}, false, err
	}
	if err := validateUpdateState(state); err != nil {
		return UpdateState{}, false, err
	}
	return state, true, nil
}

func validateUpdateState(state UpdateState) error {
	if state.Schema != UpdateStateSchema || state.RootVersion <= 0 || state.ReleaseMetadataVersion <= 0 ||
		!validDigest(state.RootSHA256) || !validDigest(state.ReleaseMetadataSHA256) {
		return errors.New("update rollback state is invalid")
	}
	if _, err := parseReleaseVersion(state.ReleaseVersion); err != nil {
		return errors.New("update rollback state has an invalid release version")
	}
	acceptedAt, err := time.Parse(time.RFC3339, state.AcceptedAt)
	if err != nil || acceptedAt.UTC().Format(time.RFC3339) != state.AcceptedAt {
		return errors.New("update rollback state has an invalid accepted_at timestamp")
	}
	return nil
}

func storeUpdateState(path string, state UpdateState) error {
	if err := validateUpdateState(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := writeAtomicPrivate(path, append(data, '\n')); err != nil {
		return fmt.Errorf("store update rollback state: %w", err)
	}
	return nil
}

func enforceUpdateStateClock(state UpdateState, exists bool, now time.Time) error {
	if !exists {
		return nil
	}
	acceptedAt, err := time.Parse(time.RFC3339, state.AcceptedAt)
	if err != nil {
		return errors.New("update rollback state has an invalid accepted_at timestamp")
	}
	if now.Before(acceptedAt.Add(-maximumClockRollback)) {
		return fmt.Errorf("system clock is more than %s behind the last accepted release metadata time", maximumClockRollback)
	}
	return nil
}

func enforceUpdateStateRollback(state UpdateState, exists bool, root *rootTrustSnapshot, release *releaseTrustSnapshot) error {
	if !exists {
		return nil
	}
	if root.metadata.Version < state.RootVersion {
		return fmt.Errorf("release root rollback from version %d to %d", state.RootVersion, root.metadata.Version)
	}
	if root.metadata.Version == state.RootVersion && root.sha256 != state.RootSHA256 {
		return errors.New("release root changed without a version increase")
	}
	if release.metadata.Version < state.ReleaseMetadataVersion {
		return fmt.Errorf("release metadata rollback from version %d to %d", state.ReleaseMetadataVersion, release.metadata.Version)
	}
	if release.metadata.Version == state.ReleaseMetadataVersion && release.sha256 != state.ReleaseMetadataSHA256 {
		return errors.New("release metadata changed without a version increase")
	}
	previousVersion, err := parseReleaseVersion(state.ReleaseVersion)
	if err != nil {
		return errors.New("update rollback state has an invalid release version")
	}
	candidateVersion, err := parseReleaseVersion(release.metadata.ReleaseVersion)
	if err != nil {
		return errors.New("authenticated release metadata has an invalid release version")
	}
	if compareVersionTriples(candidateVersion, previousVersion) < 0 {
		return fmt.Errorf("release version rollback from %s to %s", state.ReleaseVersion, release.metadata.ReleaseVersion)
	}
	return nil
}

func openPrivateUpdateState(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		_ = syscall.Close(fd)
		return nil, errors.New("update rollback state must be an owner-only single-link regular file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open update rollback state returned an invalid file handle")
	}
	return file, nil
}

func lockUpdateState(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open update state lock: %w", err)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = syscall.Close(fd)
		return nil, errors.New("update state lock must be an owner-owned single-link regular file")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("secure update state lock: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("lock update rollback state: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
		return nil, errors.New("open update state lock returned an invalid file handle")
	}
	return file, nil
}

func unlockUpdateState(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
