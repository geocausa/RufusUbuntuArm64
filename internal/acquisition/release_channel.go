package acquisition

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReleaseChannelOptions controls authenticated release metadata refresh.
type ReleaseChannelOptions struct {
	CacheDir                  string
	StatePath                 string
	Now                       time.Time
	Offline                   bool
	AllowCachedOnNetworkError bool
	AllowLoopback             bool
	HTTPClient                *http.Client
}

// ReleaseChannelResult is a read-only authenticated release-channel snapshot.
// The verified objects remain internally immutable and are accepted separately
// through the locked update rollback transaction.
type ReleaseChannelResult struct {
	RootVersion            int          `json:"root_version"`
	RootExpires            string       `json:"root_expires"`
	RootSHA256             string       `json:"root_sha256"`
	ReleaseMetadataVersion int          `json:"release_metadata_version"`
	ReleaseGenerated       string       `json:"release_generated"`
	ReleaseExpires         string       `json:"release_expires"`
	ReleaseVersion         string       `json:"release_version"`
	Tag                    string       `json:"tag"`
	Commit                 string       `json:"commit"`
	Channel                string       `json:"channel"`
	ReleaseSHA256          string       `json:"release_sha256"`
	SigningKeyIDs          []string     `json:"signing_key_ids"`
	Package                ReleaseAsset `json:"package"`
	FromCache              bool         `json:"from_cache"`
	CacheDir               string       `json:"cache_dir"`
	ReleasePath            string       `json:"release_path"`
	RollbackStatePath      string       `json:"rollback_state_path"`

	root          *VerifiedRoot
	release       *VerifiedRelease
	cacheDir      string
	configPath    string
	bootstrapPath string
	statePath     string
}

// ResolveReleaseChannelCacheDir returns the explicit directory or the
// XDG-compatible per-user cache used for authenticated release metadata.
func ResolveReleaseChannelCacheDir(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve user cache directory: %w", err)
		}
		value = filepath.Join(base, "rufusarm64", "update")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve release metadata cache: %w", err)
	}
	return absolute, nil
}

// RefreshReleaseChannel retrieves and verifies the root chain and signed release
// envelope from a package-owned pinned channel, or verifies an unexpired cached
// envelope when explicitly offline or when fallback is allowed. It never accepts
// rollback state, downloads a package, requests privilege, or installs software.
func RefreshReleaseChannel(ctx context.Context, configPath string, options ReleaseChannelOptions) (*ReleaseChannelResult, error) {
	if ctx == nil {
		return nil, errors.New("release channel context is nil")
	}
	config, configDir, err := loadChannelConfig(configPath, options.AllowLoopback)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, errors.New("the built-in update channel is not provisioned in this package; use local signed root and release metadata")
	}
	if config.ReleaseURL == "" {
		return nil, errors.New("the configured metadata channel does not publish release metadata")
	}
	configAbsolute, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return nil, fmt.Errorf("resolve release channel configuration: %w", err)
	}
	cacheDir, err := ResolveReleaseChannelCacheDir(options.CacheDir)
	if err != nil {
		return nil, err
	}
	bootstrapPath := filepath.Join(configDir, config.BootstrapRoot)
	statePath, err := ResolveUpdateStatePath(options.StatePath)
	if err != nil {
		return nil, err
	}
	if err := rejectReleaseChannelCacheCollision(cacheDir, configAbsolute, bootstrapPath); err != nil {
		return nil, err
	}
	if err := rejectReleaseChannelStateCollision(statePath, cacheDir, configAbsolute, bootstrapPath); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(cacheDir); err != nil {
		return nil, fmt.Errorf("secure release metadata cache: %w", err)
	}
	state, stateExists, err := loadUpdateState(statePath)
	if err != nil {
		return nil, err
	}
	if err := enforceUpdateStateClock(state, stateExists, options.Now); err != nil {
		return nil, err
	}

	bootstrapBytes, err := readRegularLimited(bootstrapPath, MaxRootMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read update bootstrap root metadata: %w", err)
	}
	root, err := VerifyBootstrapRoot(bootstrapBytes, options.Now)
	if err != nil {
		return nil, fmt.Errorf("verify update bootstrap root metadata: %w", err)
	}
	root, err = replayCachedRoots(root, cacheDir, options.Now)
	if err != nil {
		return nil, err
	}

	fetchOptions := ChannelOptions{Now: options.Now, AllowLoopback: options.AllowLoopback, HTTPClient: options.HTTPClient}
	var networkErr error
	if !options.Offline {
		for updateCount := 0; ; updateCount++ {
			snapshot, snapshotErr := root.trustSnapshot()
			if snapshotErr != nil {
				return nil, snapshotErr
			}
			nextVersion := snapshot.metadata.Version + 1
			rootURL, urlErr := channelRootMetadataURL(config.RootURL, nextVersion)
			if urlErr != nil {
				return nil, urlErr
			}
			rootBytes, fetchErr := fetchChannelMetadata(ctx, rootURL, config.AllowedHosts, MaxRootMetadataBytes, fetchOptions)
			if errors.Is(fetchErr, errChannelMetadataNotFound) {
				break
			}
			if fetchErr != nil {
				networkErr = fmt.Errorf("refresh update root metadata version %d: %w", nextVersion, fetchErr)
				break
			}
			if updateCount >= maxChannelRootUpdates {
				return nil, fmt.Errorf("update root metadata chain exceeds the %d-update safety limit", maxChannelRootUpdates)
			}
			candidate, verifyErr := VerifyRootUpdate(root, rootBytes, options.Now)
			if verifyErr != nil {
				return nil, verifyErr
			}
			if err := storeRootHistory(cacheDir, candidate, rootBytes); err != nil {
				return nil, err
			}
			root = candidate
		}
	}
	if err := enforceReleaseChannelRootState(state, stateExists, root); err != nil {
		return nil, err
	}

	if options.Offline || networkErr != nil {
		if !options.Offline && !options.AllowCachedOnNetworkError {
			return nil, networkErr
		}
		cached, cacheErr := loadCachedReleaseChannel(root, cacheDir, statePath, state, stateExists, options.Now, configAbsolute, bootstrapPath)
		if cacheErr != nil {
			if networkErr != nil {
				return nil, fmt.Errorf("%v; cached release metadata unavailable: %w", networkErr, cacheErr)
			}
			return nil, cacheErr
		}
		cached.FromCache = true
		return cached, nil
	}

	releaseBytes, err := fetchChannelMetadata(ctx, config.ReleaseURL, config.AllowedHosts, MaxReleaseMetadataBytes, fetchOptions)
	if err != nil {
		if options.AllowCachedOnNetworkError {
			cached, cacheErr := loadCachedReleaseChannel(root, cacheDir, statePath, state, stateExists, options.Now, configAbsolute, bootstrapPath)
			if cacheErr == nil {
				cached.FromCache = true
				return cached, nil
			}
			return nil, fmt.Errorf("refresh release metadata: %w; cached release metadata unavailable: %v", err, cacheErr)
		}
		return nil, fmt.Errorf("refresh release metadata: %w", err)
	}
	release, err := VerifyReleaseMetadata(root, releaseBytes, options.Now)
	if err != nil {
		return nil, err
	}
	if err := enforceReleaseChannelRollback(state, stateExists, root, release); err != nil {
		return nil, err
	}
	releasePath := filepath.Join(cacheDir, "release.json")
	if err := writeAtomicPrivate(releasePath, releaseBytes); err != nil {
		return nil, fmt.Errorf("cache verified release metadata: %w", err)
	}
	return releaseChannelResult(root, release, false, cacheDir, releasePath, statePath, configAbsolute, bootstrapPath)
}

// Accept commits this authenticated refresh through the locked rollback state.
func (result *ReleaseChannelResult) Accept(currentVersion string, options UpdateStateOptions) (UpdateStateResult, error) {
	if result == nil || result.root == nil || result.release == nil {
		return UpdateStateResult{}, errors.New("authenticated release channel result is required")
	}
	statePath, err := ResolveUpdateStatePath(options.Path)
	if err != nil {
		return UpdateStateResult{}, err
	}
	if filepath.Clean(statePath) != filepath.Clean(result.statePath) {
		return UpdateStateResult{}, errors.New("release channel acceptance must use the rollback state checked during refresh")
	}
	if err := rejectReleaseChannelStateCollision(statePath, result.cacheDir, result.configPath, result.bootstrapPath); err != nil {
		return UpdateStateResult{}, err
	}
	now := normalizedChannelNow(options.Now)
	rootSnapshot, err := result.root.trustSnapshot()
	if err != nil {
		return UpdateStateResult{}, err
	}
	releaseSnapshot, err := result.release.trustSnapshot()
	if err != nil {
		return UpdateStateResult{}, err
	}
	if !rootSnapshot.expiresAt.After(now) {
		return UpdateStateResult{}, fmt.Errorf("trusted update root version %d has expired", rootSnapshot.metadata.Version)
	}
	releaseExpires, err := time.Parse(time.RFC3339, releaseSnapshot.metadata.Expires)
	if err != nil {
		return UpdateStateResult{}, errors.New("authenticated release metadata has an invalid expiry")
	}
	if !releaseExpires.After(now) {
		return UpdateStateResult{}, fmt.Errorf("release metadata version %d has expired", releaseSnapshot.metadata.Version)
	}
	options.Now = now
	return AcceptReleaseMetadata(result.root, result.release, currentVersion, options)
}

func loadCachedReleaseChannel(root *VerifiedRoot, cacheDir, statePath string, state UpdateState, stateExists bool, now time.Time, configPath, bootstrapPath string) (*ReleaseChannelResult, error) {
	releasePath := filepath.Join(cacheDir, "release.json")
	data, err := readRegularLimited(releasePath, MaxReleaseMetadataBytes)
	if err != nil {
		return nil, err
	}
	release, err := VerifyReleaseMetadata(root, data, now)
	if err != nil {
		return nil, err
	}
	if err := enforceReleaseChannelRollback(state, stateExists, root, release); err != nil {
		return nil, err
	}
	return releaseChannelResult(root, release, true, cacheDir, releasePath, statePath, configPath, bootstrapPath)
}

func releaseChannelResult(root *VerifiedRoot, release *VerifiedRelease, fromCache bool, cacheDir, releasePath, statePath, configPath, bootstrapPath string) (*ReleaseChannelResult, error) {
	rootSnapshot, err := root.trustSnapshot()
	if err != nil {
		return nil, err
	}
	releaseSnapshot, err := release.trustSnapshot()
	if err != nil {
		return nil, err
	}
	packageAsset, err := release.Package()
	if err != nil {
		return nil, err
	}
	return &ReleaseChannelResult{
		RootVersion: rootSnapshot.metadata.Version, RootExpires: rootSnapshot.expiresAt.Format(time.RFC3339), RootSHA256: rootSnapshot.sha256,
		ReleaseMetadataVersion: releaseSnapshot.metadata.Version, ReleaseGenerated: releaseSnapshot.metadata.Generated,
		ReleaseExpires: releaseSnapshot.metadata.Expires, ReleaseVersion: releaseSnapshot.metadata.ReleaseVersion,
		Tag: releaseSnapshot.metadata.Tag, Commit: releaseSnapshot.metadata.Commit, Channel: releaseSnapshot.metadata.Channel,
		ReleaseSHA256: releaseSnapshot.sha256, SigningKeyIDs: append([]string(nil), releaseSnapshot.signingKeyIDs...),
		Package: packageAsset, FromCache: fromCache, CacheDir: cacheDir, ReleasePath: releasePath, RollbackStatePath: statePath,
		root: root, release: release, cacheDir: cacheDir, configPath: configPath, bootstrapPath: bootstrapPath, statePath: statePath,
	}, nil
}

func enforceReleaseChannelRootState(state UpdateState, exists bool, root *VerifiedRoot) error {
	if !exists {
		return nil
	}
	snapshot, err := root.trustSnapshot()
	if err != nil {
		return err
	}
	if snapshot.metadata.Version < state.RootVersion {
		return fmt.Errorf("update root metadata rollback from accepted version %d to %d", state.RootVersion, snapshot.metadata.Version)
	}
	if snapshot.metadata.Version == state.RootVersion && snapshot.sha256 != state.RootSHA256 {
		return errors.New("update root metadata changed without a version increase")
	}
	return nil
}

func enforceReleaseChannelRollback(state UpdateState, exists bool, root *VerifiedRoot, release *VerifiedRelease) error {
	if !exists {
		return nil
	}
	rootSnapshot, err := root.trustSnapshot()
	if err != nil {
		return err
	}
	releaseSnapshot, err := release.trustSnapshot()
	if err != nil {
		return err
	}
	return enforceUpdateStateRollback(state, true, rootSnapshot, releaseSnapshot)
}

func rejectReleaseChannelCacheCollision(cacheDir, configPath, bootstrapPath string) error {
	configDir := filepath.Dir(configPath)
	cacheInsideConfig, err := pathWithin(cacheDir, configDir)
	if err != nil {
		return err
	}
	configInsideCache, err := pathWithin(configDir, cacheDir)
	if err != nil {
		return err
	}
	if cacheInsideConfig || configInsideCache {
		return errors.New("release metadata cache must not overlap the trusted channel configuration directory")
	}
	for _, protected := range []string{configPath, bootstrapPath} {
		collides, err := pathsCollide(cacheDir, protected)
		if err != nil {
			return err
		}
		if collides {
			return fmt.Errorf("release metadata cache collides with trusted channel input %s", protected)
		}
	}
	return nil
}

func rejectReleaseChannelStateCollision(statePath, cacheDir, configPath, bootstrapPath string) error {
	for _, candidate := range []string{statePath, statePath + ".lock"} {
		inside, err := pathWithin(candidate, cacheDir)
		if err != nil {
			return err
		}
		if inside {
			return errors.New("update rollback state and lock must remain outside the release metadata cache")
		}
		for _, protected := range []string{configPath, bootstrapPath} {
			collides, err := pathsCollide(candidate, protected)
			if err != nil {
				return err
			}
			if collides {
				return fmt.Errorf("update rollback state collides with trusted channel input %s", protected)
			}
		}
	}
	return nil
}

func pathWithin(candidate, directory string) (bool, error) {
	candidateAbsolute, err := filepath.Abs(candidate)
	if err != nil {
		return false, err
	}
	directoryAbsolute, err := filepath.Abs(directory)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(directoryAbsolute, candidateAbsolute)
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

func pathsCollide(left, right string) (bool, error) {
	leftAbsolute, err := filepath.Abs(left)
	if err != nil {
		return false, err
	}
	rightAbsolute, err := filepath.Abs(right)
	if err != nil {
		return false, err
	}
	if filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute) {
		return true, nil
	}
	leftInfo, leftErr := os.Lstat(leftAbsolute)
	rightInfo, rightErr := os.Lstat(rightAbsolute)
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, leftErr
	}
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, rightErr
	}
	return false, nil
}
