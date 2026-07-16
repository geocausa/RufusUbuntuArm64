package acquisition

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	channelOPath            = 0x200000
	channelRootVersionToken = "{version}"
	maxChannelRootUpdates   = 32
	maximumClockRollback    = 24 * time.Hour

	ChannelConfigSchema   = 1
	ChannelStateSchema    = 1
	MaxChannelConfigBytes = 64 * 1024
	MaxChannelStateBytes  = 64 * 1024
)

type ChannelConfig struct {
	Schema        int      `json:"schema"`
	Enabled       bool     `json:"enabled"`
	BootstrapRoot string   `json:"bootstrap_root"`
	RootURL       string   `json:"root_url"`
	CatalogURL    string   `json:"catalog_url"`
	AllowedHosts  []string `json:"allowed_hosts"`
}

type ChannelState struct {
	Schema         int    `json:"schema"`
	RootVersion    int    `json:"root_version"`
	RootSHA256     string `json:"root_sha256"`
	CatalogVersion int    `json:"catalog_version"`
	CatalogSHA256  string `json:"catalog_sha256"`
	AcceptedAt     string `json:"accepted_at"`
}

type ChannelOptions struct {
	CacheDir                  string
	Now                       time.Time
	Offline                   bool
	AllowCachedOnNetworkError bool
	AllowLoopback             bool
	HTTPClient                *http.Client
}

type ChannelResult struct {
	RootVersion      int      `json:"root_version"`
	RootExpires      string   `json:"root_expires"`
	RootSHA256       string   `json:"root_sha256"`
	CatalogVersion   int      `json:"catalog_version"`
	CatalogGenerated string   `json:"catalog_generated"`
	CatalogExpires   string   `json:"catalog_expires"`
	CatalogSHA256    string   `json:"catalog_sha256"`
	SigningKeyIDs    []string `json:"signing_key_ids"`
	Images           []Image  `json:"images"`
	FromCache        bool     `json:"from_cache"`
}

func RefreshChannel(ctx context.Context, configPath string, options ChannelOptions) (*ChannelResult, error) {
	config, configDir, err := loadChannelConfig(configPath, options.AllowLoopback)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, errors.New("the built-in acquisition channel is not provisioned in this package; use the advanced local signed-catalog workflow")
	}
	cacheDir, err := resolveChannelCacheDir(options.CacheDir)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(cacheDir); err != nil {
		return nil, err
	}
	bootstrapPath := filepath.Join(configDir, config.BootstrapRoot)
	bootstrapBytes, err := readRegularLimited(bootstrapPath, MaxRootMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap root metadata: %w", err)
	}
	root, err := VerifyBootstrapRoot(bootstrapBytes, options.Now)
	if err != nil {
		return nil, fmt.Errorf("verify bootstrap root metadata: %w", err)
	}
	root, err = replayCachedRoots(root, cacheDir, options.Now)
	if err != nil {
		return nil, err
	}
	state, stateExists, err := loadChannelState(filepath.Join(cacheDir, "state.json"))
	if err != nil {
		return nil, err
	}
	if stateExists {
		if state.RootVersion > root.Metadata.Version {
			return nil, fmt.Errorf("trusted root state records version %d but cached root history reaches only %d; refusing rollback", state.RootVersion, root.Metadata.Version)
		}
		if state.RootVersion == root.Metadata.Version && state.RootSHA256 != root.SHA256 {
			return nil, errors.New("trusted root state digest does not match cached root metadata")
		}
	}

	if err := enforceChannelClock(state, stateExists, options.Now); err != nil {
		return nil, err
	}

	var networkErr error
	if !options.Offline {
		for updateCount := 0; ; updateCount++ {
			nextVersion := root.Metadata.Version + 1
			rootURL, urlErr := channelRootMetadataURL(config.RootURL, nextVersion)
			if urlErr != nil {
				return nil, urlErr
			}
			rootBytes, fetchErr := fetchChannelMetadata(ctx, rootURL, config.AllowedHosts, MaxRootMetadataBytes, options)
			if errors.Is(fetchErr, errChannelMetadataNotFound) {
				break
			}
			if fetchErr != nil {
				networkErr = fmt.Errorf("refresh root metadata version %d: %w", nextVersion, fetchErr)
				break
			}
			if updateCount >= maxChannelRootUpdates {
				return nil, fmt.Errorf("root metadata chain exceeds the %d-update safety limit", maxChannelRootUpdates)
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

	if options.Offline || networkErr != nil {
		if !options.Offline && !options.AllowCachedOnNetworkError {
			return nil, networkErr
		}
		cached, cacheErr := loadCachedChannelCatalog(root, cacheDir, state, stateExists, options.Now)
		if cacheErr != nil {
			if networkErr != nil {
				return nil, fmt.Errorf("%v; cached catalog unavailable: %w", networkErr, cacheErr)
			}
			return nil, cacheErr
		}
		cached.FromCache = true
		if err := storeAcceptedChannelState(cacheDir, cached, state, stateExists, options.Now); err != nil {
			return nil, err
		}
		return cached, nil
	}

	catalogBytes, err := fetchChannelMetadata(ctx, config.CatalogURL, config.AllowedHosts, MaxChannelCatalogBytes, options)
	if err != nil {
		if options.AllowCachedOnNetworkError {
			cached, cacheErr := loadCachedChannelCatalog(root, cacheDir, state, stateExists, options.Now)
			if cacheErr == nil {
				cached.FromCache = true
				if err := storeAcceptedChannelState(cacheDir, cached, state, stateExists, options.Now); err != nil {
					return nil, err
				}
				return cached, nil
			}
			return nil, fmt.Errorf("refresh catalog metadata: %w; cached catalog unavailable: %v", err, cacheErr)
		}
		return nil, fmt.Errorf("refresh catalog metadata: %w", err)
	}
	catalog, err := VerifyChannelCatalog(root, catalogBytes, options.Now)
	if err != nil {
		return nil, err
	}
	if err := enforceChannelRollback(state, stateExists, root, catalog); err != nil {
		return nil, err
	}
	if err := writeAtomicPrivate(filepath.Join(cacheDir, "catalog.json"), catalogBytes); err != nil {
		return nil, fmt.Errorf("cache verified catalog: %w", err)
	}
	result := channelResult(root, catalog, false)
	if err := storeAcceptedChannelState(cacheDir, result, state, stateExists, options.Now); err != nil {
		return nil, err
	}
	return result, nil
}

func (result *ChannelResult) Find(id string) (Image, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, image := range result.Images {
		if image.ID == id {
			return image, nil
		}
	}
	return Image{}, fmt.Errorf("channel image %q was not found", id)
}

func loadChannelConfig(path string, allowLoopback bool) (ChannelConfig, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ChannelConfig{}, "", errors.New("channel configuration path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ChannelConfig{}, "", fmt.Errorf("resolve channel configuration: %w", err)
	}
	data, err := readRegularLimited(absolute, MaxChannelConfigBytes)
	if err != nil {
		return ChannelConfig{}, "", fmt.Errorf("read channel configuration: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return ChannelConfig{}, "", err
	}
	var config ChannelConfig
	if err := decodeStrictJSON(data, &config, "channel configuration"); err != nil {
		return ChannelConfig{}, "", err
	}
	if config.Schema != ChannelConfigSchema {
		return ChannelConfig{}, "", fmt.Errorf("unsupported channel configuration schema %d", config.Schema)
	}
	if !config.Enabled {
		return config, filepath.Dir(absolute), nil
	}
	if config.BootstrapRoot == "" || filepath.Base(config.BootstrapRoot) != config.BootstrapRoot || strings.ContainsAny(config.BootstrapRoot, `/\\`) {
		return ChannelConfig{}, "", errors.New("bootstrap_root must be a sibling filename")
	}
	if len(config.AllowedHosts) == 0 || len(config.AllowedHosts) > 16 {
		return ChannelConfig{}, "", errors.New("allowed_hosts must contain between 1 and 16 hosts")
	}
	seen := make(map[string]struct{}, len(config.AllowedHosts))
	previous := ""
	for index, host := range config.AllowedHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if err := validateChannelHost(host, allowLoopback); err != nil {
			return ChannelConfig{}, "", fmt.Errorf("allowed_hosts[%d]: %w", index, err)
		}
		if _, ok := seen[host]; ok {
			return ChannelConfig{}, "", fmt.Errorf("duplicate allowed host %q", host)
		}
		if previous != "" && host <= previous {
			return ChannelConfig{}, "", errors.New("allowed_hosts must be sorted")
		}
		previous = host
		seen[host] = struct{}{}
		config.AllowedHosts[index] = host
	}
	if strings.Count(config.RootURL, channelRootVersionToken) != 1 {
		return ChannelConfig{}, "", errors.New("root_url must contain exactly one {version} token")
	}
	rootTemplate, err := url.Parse(config.RootURL)
	if err != nil || !strings.Contains(rootTemplate.Path, channelRootVersionToken) || strings.Contains(rootTemplate.Host, channelRootVersionToken) || strings.Contains(rootTemplate.RawQuery, channelRootVersionToken) {
		return ChannelConfig{}, "", errors.New("root_url {version} token must appear only in the URL path")
	}
	rootURL, err := channelRootMetadataURL(config.RootURL, 1)
	if err != nil {
		return ChannelConfig{}, "", fmt.Errorf("root_url: %w", err)
	}
	if err := validateChannelMetadataURL(rootURL, seen, allowLoopback); err != nil {
		return ChannelConfig{}, "", fmt.Errorf("root_url: %w", err)
	}
	if err := validateChannelMetadataURL(config.CatalogURL, seen, allowLoopback); err != nil {
		return ChannelConfig{}, "", fmt.Errorf("catalog_url: %w", err)
	}
	return config, filepath.Dir(absolute), nil
}

func channelRootMetadataURL(template string, version int) (string, error) {
	if version <= 0 || strings.Count(template, channelRootVersionToken) != 1 {
		return "", errors.New("root metadata URL template or version is invalid")
	}
	return strings.Replace(template, channelRootVersionToken, strconv.Itoa(version), 1), nil
}

func validateChannelMetadataURL(value string, allowed map[string]struct{}, allowLoopback bool) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "https" || host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("metadata URL must be an absolute HTTPS URL without user information or a fragment")
	}
	if parsed.Port() != "" && parsed.Port() != "443" && !(allowLoopback && isLoopbackHost(host)) {
		return errors.New("metadata HTTPS URL must use the default port")
	}
	if _, ok := allowed[host]; !ok {
		return fmt.Errorf("metadata host %q is not allowlisted", host)
	}
	return validateChannelHost(host, allowLoopback)
}

func validateChannelHost(host string, allowLoopback bool) error {
	if allowLoopback && isLoopbackHost(host) {
		return nil
	}
	return validateHostname(host)
}

func resolveChannelCacheDir(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve user cache directory: %w", err)
		}
		value = filepath.Join(base, "rufusarm64", "acquisition")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve acquisition cache: %w", err)
	}
	return absolute, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create acquisition cache: %w", err)
	}
	pathFD, err := syscall.Open(path, channelOPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("acquisition cache is not a real directory: %w", err)
	}
	defer syscall.Close(pathFD)
	var pathStat syscall.Stat_t
	if err := syscall.Fstat(pathFD, &pathStat); err != nil || pathStat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("acquisition cache is not a real directory")
	}
	directoryFD, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open acquisition cache directory: %w", err)
	}
	defer syscall.Close(directoryFD)
	var directoryStat syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryStat); err != nil {
		return err
	}
	verifyFD, err := syscall.Open(path, channelOPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("acquisition cache changed while it was being opened")
	}
	defer syscall.Close(verifyFD)
	var verifyStat syscall.Stat_t
	if err := syscall.Fstat(verifyFD, &verifyStat); err != nil || verifyStat.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		directoryStat.Dev != verifyStat.Dev || directoryStat.Ino != verifyStat.Ino ||
		pathStat.Dev != verifyStat.Dev || pathStat.Ino != verifyStat.Ino {
		return errors.New("acquisition cache changed while it was being opened")
	}
	if err := syscall.Fchmod(directoryFD, 0o700); err != nil {
		return fmt.Errorf("secure acquisition cache: %w", err)
	}
	return nil
}

func replayCachedRoots(root *VerifiedRoot, cacheDir string, now time.Time) (*VerifiedRoot, error) {
	rootsDir := filepath.Join(cacheDir, "roots")
	if err := ensurePrivateDirectory(rootsDir); err != nil {
		return nil, fmt.Errorf("secure root history directory: %w", err)
	}
	for next := root.Metadata.Version + 1; ; next++ {
		path := filepath.Join(rootsDir, fmt.Sprintf("root.%d.json", next))
		data, err := readRegularLimited(path, MaxRootMetadataBytes)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read cached root version %d: %w", next, err)
		}
		updated, err := VerifyRootUpdate(root, data, now)
		if err != nil {
			return nil, fmt.Errorf("verify cached root version %d: %w", next, err)
		}
		root = updated
	}
	return root, nil
}

func storeRootHistory(cacheDir string, root *VerifiedRoot, envelope []byte) error {
	path := filepath.Join(cacheDir, "roots", fmt.Sprintf("root.%d.json", root.Metadata.Version))
	if existing, err := readRegularLimited(path, MaxRootMetadataBytes); err == nil {
		if string(existing) == string(envelope) {
			return nil
		}
		return fmt.Errorf("cached root version %d already exists with different content", root.Metadata.Version)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAtomicPrivate(path, envelope); err != nil {
		return fmt.Errorf("store root version %d: %w", root.Metadata.Version, err)
	}
	return nil
}

func loadChannelState(path string) (ChannelState, bool, error) {
	data, err := readRegularLimited(path, MaxChannelStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return ChannelState{}, false, nil
	}
	if err != nil {
		return ChannelState{}, false, fmt.Errorf("read acquisition trust state: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return ChannelState{}, false, err
	}
	var state ChannelState
	if err := decodeStrictJSON(data, &state, "acquisition trust state"); err != nil {
		return ChannelState{}, false, err
	}
	if state.Schema != ChannelStateSchema || state.RootVersion <= 0 || state.CatalogVersion <= 0 || !validDigest(state.RootSHA256) || !validDigest(state.CatalogSHA256) {
		return ChannelState{}, false, errors.New("acquisition trust state is invalid")
	}
	acceptedAt, err := time.Parse(time.RFC3339, state.AcceptedAt)
	if err != nil || acceptedAt.UTC().Format(time.RFC3339) != state.AcceptedAt {
		return ChannelState{}, false, errors.New("acquisition trust state has an invalid accepted_at timestamp")
	}
	return state, true, nil
}

func storeChannelState(path string, state ChannelState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := writeAtomicPrivate(path, append(data, '\n')); err != nil {
		return fmt.Errorf("store acquisition trust state: %w", err)
	}
	return nil
}

func normalizedChannelNow(value time.Time) time.Time {
	if value.IsZero() {
		value = time.Now()
	}
	return value.UTC().Truncate(time.Second)
}

func enforceChannelClock(state ChannelState, exists bool, now time.Time) error {
	if !exists {
		return nil
	}
	acceptedAt, err := time.Parse(time.RFC3339, state.AcceptedAt)
	if err != nil {
		return errors.New("acquisition trust state has an invalid accepted_at timestamp")
	}
	if normalizedChannelNow(now).Before(acceptedAt.Add(-maximumClockRollback)) {
		return fmt.Errorf("system clock is more than %s behind the last accepted acquisition metadata time", maximumClockRollback)
	}
	return nil
}

func storeAcceptedChannelState(cacheDir string, result *ChannelResult, previous ChannelState, previousExists bool, now time.Time) error {
	acceptedAt := normalizedChannelNow(now)
	if previousExists {
		previousTime, err := time.Parse(time.RFC3339, previous.AcceptedAt)
		if err != nil {
			return err
		}
		if previousTime.After(acceptedAt) {
			acceptedAt = previousTime
		}
	}
	state := ChannelState{
		Schema:         ChannelStateSchema,
		RootVersion:    result.RootVersion,
		RootSHA256:     result.RootSHA256,
		CatalogVersion: result.CatalogVersion,
		CatalogSHA256:  result.CatalogSHA256,
		AcceptedAt:     acceptedAt.UTC().Format(time.RFC3339),
	}
	return storeChannelState(filepath.Join(cacheDir, "state.json"), state)
}

func enforceChannelRollback(state ChannelState, exists bool, root *VerifiedRoot, catalog *VerifiedChannelCatalog) error {
	if !exists {
		return nil
	}
	if root.Metadata.Version < state.RootVersion {
		return fmt.Errorf("root metadata rollback from version %d to %d", state.RootVersion, root.Metadata.Version)
	}
	if root.Metadata.Version == state.RootVersion && root.SHA256 != state.RootSHA256 {
		return errors.New("root metadata changed without a version increase")
	}
	if catalog.Metadata.Version < state.CatalogVersion {
		return fmt.Errorf("catalog rollback from version %d to %d", state.CatalogVersion, catalog.Metadata.Version)
	}
	if catalog.Metadata.Version == state.CatalogVersion && catalog.SHA256 != state.CatalogSHA256 {
		return errors.New("catalog metadata changed without a version increase")
	}
	return nil
}

func loadCachedChannelCatalog(root *VerifiedRoot, cacheDir string, state ChannelState, stateExists bool, now time.Time) (*ChannelResult, error) {
	data, err := readRegularLimited(filepath.Join(cacheDir, "catalog.json"), MaxChannelCatalogBytes)
	if err != nil {
		return nil, err
	}
	catalog, err := VerifyChannelCatalog(root, data, now)
	if err != nil {
		return nil, err
	}
	if err := enforceChannelRollback(state, stateExists, root, catalog); err != nil {
		return nil, err
	}
	return channelResult(root, catalog, true), nil
}

func channelResult(root *VerifiedRoot, catalog *VerifiedChannelCatalog, fromCache bool) *ChannelResult {
	return &ChannelResult{
		RootVersion:      root.Metadata.Version,
		RootExpires:      root.ExpiresAt.Format(time.RFC3339),
		RootSHA256:       root.SHA256,
		CatalogVersion:   catalog.Metadata.Version,
		CatalogGenerated: catalog.GeneratedAt.Format(time.RFC3339),
		CatalogExpires:   catalog.ExpiresAt.Format(time.RFC3339),
		CatalogSHA256:    catalog.SHA256,
		SigningKeyIDs:    append([]string(nil), catalog.SigningKeyIDs...),
		Images:           append([]Image(nil), catalog.Metadata.Images...),
		FromCache:        fromCache,
	}
}

var errChannelMetadataNotFound = errors.New("channel metadata not found")

func fetchChannelMetadata(ctx context.Context, value string, allowedHosts []string, limit int, options ChannelOptions) ([]byte, error) {
	client := channelHTTPClient(allowedHosts, options)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, value, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "RufusUbuntuArm64-channel/1")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errChannelMetadataNotFound
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", response.Status)
	}
	if response.ContentLength > int64(limit) {
		return nil, fmt.Errorf("metadata exceeds the %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > limit {
		return nil, fmt.Errorf("metadata size must be between 1 and %d bytes", limit)
	}
	return data, nil
}

func channelHTTPClient(allowedHosts []string, options ChannelOptions) *http.Client {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		allowed[strings.ToLower(host)] = struct{}{}
	}
	var client http.Client
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyFromEnvironment
		transport.DisableCompression = true
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		transport.DialContext = (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		transport.ResponseHeaderTimeout = 30 * time.Second
		transport.IdleConnTimeout = 90 * time.Second
		client.Transport = transport
		client.Timeout = 60 * time.Second
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many metadata redirects")
		}
		host := strings.ToLower(request.URL.Hostname())
		if request.URL.Scheme != "https" {
			return errors.New("refusing metadata redirect to a non-HTTPS URL")
		}
		if request.URL.Port() != "" && request.URL.Port() != "443" && !(options.AllowLoopback && isLoopbackHost(host)) {
			return errors.New("refusing metadata redirect to a non-default HTTPS port")
		}
		if _, ok := allowed[host]; !ok {
			return fmt.Errorf("refusing metadata redirect to non-allowlisted host %q", host)
		}
		return validateChannelHost(host, options.AllowLoopback)
	}
	return &client
}

func readRegularLimited(path string, limit int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input is not a real regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, info) {
		return nil, errors.New("input changed while it was being opened")
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, fmt.Errorf("input is not a regular file within the %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	return data, nil
}

func writeAtomicPrivate(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace non-regular trust state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(directory, ".rufus-trust-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return syncDirectory(directory)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
