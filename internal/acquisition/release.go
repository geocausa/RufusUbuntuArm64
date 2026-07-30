package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	MaxReleaseMetadataBytes = 512 * 1024
	maxReleaseMetadataLife  = 45 * 24 * time.Hour
	maximumReleaseAssets    = 32
	maximumReleaseAssetSize = 8 * 1024 * 1024 * 1024
)

// ReleaseAsset binds one immutable published release object.
type ReleaseAsset struct {
	Name          string   `json:"name"`
	Size          uint64   `json:"size"`
	SHA256        string   `json:"sha256"`
	URL           string   `json:"url"`
	RedirectHosts []string `json:"redirect_hosts,omitempty"`
}

// ReleaseMetadata is threshold-signed update metadata. Verification is
// read-only: accepting this document never downloads or installs an update.
type ReleaseMetadata struct {
	Type           string         `json:"_type"`
	Schema         int            `json:"schema"`
	Version        int            `json:"version"`
	Generated      string         `json:"generated"`
	Expires        string         `json:"expires"`
	Product        string         `json:"product"`
	Repository     string         `json:"repository"`
	ReleaseVersion string         `json:"release_version"`
	Tag            string         `json:"tag"`
	Commit         string         `json:"commit"`
	Channel        string         `json:"channel"`
	Assets         []ReleaseAsset `json:"assets"`
}

// VerifiedRelease contains authenticated release metadata and signer evidence.
type VerifiedRelease struct {
	Metadata      ReleaseMetadata
	GeneratedAt   time.Time
	ExpiresAt     time.Time
	SHA256        string
	SignedBytes   []byte
	SigningKeyIDs []string
	trusted       *releaseTrustSnapshot
}

type releaseTrustSnapshot struct {
	metadata      ReleaseMetadata
	sha256        string
	signingKeyIDs []string
}

// UpdateDecision is a non-destructive comparison between the running version
// and authenticated release metadata.
type UpdateDecision struct {
	CurrentVersion  string       `json:"current_version"`
	ReleaseVersion  string       `json:"release_version"`
	MetadataVersion int          `json:"metadata_version"`
	UpdateAvailable bool         `json:"update_available"`
	Tag             string       `json:"tag"`
	Commit          string       `json:"commit"`
	Channel         string       `json:"channel"`
	Package         ReleaseAsset `json:"package"`
	MetadataSHA256  string       `json:"metadata_sha256"`
	SigningKeyIDs   []string     `json:"signing_key_ids"`
}

// VerifyReleaseMetadata authenticates one release envelope through the optional
// release role in the trusted root.
func VerifyReleaseMetadata(root *VerifiedRoot, data []byte, now time.Time) (*VerifiedRelease, error) {
	if root == nil {
		return nil, errors.New("trusted root is required")
	}
	if root.Metadata.Roles.Release == nil {
		return nil, errors.New("trusted root does not authorize a release role")
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if !root.ExpiresAt.After(now) {
		return nil, fmt.Errorf("trusted root version %d has expired; install refreshed root metadata or a newer package", root.Metadata.Version)
	}
	envelope, canonical, err := parseMetadataEnvelope(data, MaxReleaseMetadataBytes)
	if err != nil {
		return nil, err
	}
	var metadata ReleaseMetadata
	if err := decodeStrictJSON(canonical, &metadata, "release metadata"); err != nil {
		return nil, err
	}
	verified, err := prepareReleasePayload(metadata, canonical, now)
	if err != nil {
		return nil, err
	}
	keyIDs, err := verifyRoleSignatures(*root.Metadata.Roles.Release, root.keys, canonical, envelope.Signatures)
	if err != nil {
		return nil, fmt.Errorf("verify release signatures: %w", err)
	}
	verified.SigningKeyIDs = append([]string(nil), keyIDs...)
	verified.trusted = &releaseTrustSnapshot{
		metadata:      cloneReleaseMetadata(verified.Metadata),
		sha256:        verified.SHA256,
		signingKeyIDs: append([]string(nil), keyIDs...),
	}
	return verified, nil
}

func prepareReleasePayload(metadata ReleaseMetadata, canonical []byte, now time.Time) (*VerifiedRelease, error) {
	generated, expires, err := validateMetadataTimes(metadata.Generated, metadata.Expires, now, maxReleaseMetadataLife, "release", true)
	if err != nil {
		return nil, err
	}
	if metadata.Type != "release" || metadata.Schema != TrustSchemaVersion || metadata.Version <= 0 {
		return nil, errors.New("release metadata type, schema, or version is invalid")
	}
	if metadata.Product != "RufusArm64" || metadata.Repository != "geocausa/RufusUbuntuArm64" {
		return nil, errors.New("release product or repository is invalid")
	}
	if _, err := parseReleaseVersion(metadata.ReleaseVersion); err != nil {
		return nil, fmt.Errorf("release version: %w", err)
	}
	if metadata.Tag != "v"+metadata.ReleaseVersion {
		return nil, errors.New("release tag must exactly match v<release_version>")
	}
	if !validCommitSHA(metadata.Commit) {
		return nil, errors.New("release commit must be a lowercase 40-character hexadecimal SHA-1 value")
	}
	if metadata.Channel != "stable" && metadata.Channel != "prerelease" {
		return nil, errors.New("release channel must be stable or prerelease")
	}
	if len(metadata.Assets) == 0 || len(metadata.Assets) > maximumReleaseAssets {
		return nil, fmt.Errorf("release must contain between 1 and %d assets", maximumReleaseAssets)
	}
	previous := ""
	packageName := fmt.Sprintf("rufusarm64_%s_arm64.deb", metadata.ReleaseVersion)
	packageCount := 0
	for index := range metadata.Assets {
		asset := &metadata.Assets[index]
		if err := validateReleaseAsset(*asset, metadata.Repository, metadata.Tag); err != nil {
			return nil, fmt.Errorf("release asset %d: %w", index+1, err)
		}
		if previous != "" && asset.Name <= previous {
			return nil, errors.New("release assets must be sorted by name and unique")
		}
		previous = asset.Name
		if asset.Name == packageName {
			packageCount++
		}
	}
	if packageCount != 1 {
		return nil, fmt.Errorf("release must contain exactly one ARM64 package named %s", packageName)
	}
	digest := sha256.Sum256(canonical)
	return &VerifiedRelease{
		Metadata:    metadata,
		GeneratedAt: generated,
		ExpiresAt:   expires,
		SHA256:      hex.EncodeToString(digest[:]),
		SignedBytes: append([]byte(nil), canonical...),
	}, nil
}

func validateReleaseAsset(asset ReleaseAsset, repository, tag string) error {
	if !validReleaseAssetName(asset.Name) {
		return errors.New("asset name is invalid")
	}
	if asset.Size == 0 || asset.Size > maximumReleaseAssetSize {
		return fmt.Errorf("asset size must be between 1 and %d bytes", uint64(maximumReleaseAssetSize))
	}
	if len(asset.SHA256) != sha256.Size*2 || strings.ToLower(asset.SHA256) != asset.SHA256 {
		return errors.New("asset SHA-256 must be lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(asset.SHA256); err != nil {
		return errors.New("asset SHA-256 must be lowercase hexadecimal")
	}
	parsed, err := url.Parse(asset.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("asset URL must be an exact HTTPS GitHub release URL")
	}
	expectedPath := "/" + repository + "/releases/download/" + tag + "/" + asset.Name
	if parsed.EscapedPath() != expectedPath || parsed.Path != expectedPath {
		return errors.New("asset URL path does not match repository, tag, and asset name")
	}
	if len(asset.RedirectHosts) > 8 {
		return errors.New("asset redirect host list is too large")
	}
	previous := ""
	for _, host := range asset.RedirectHosts {
		if host != strings.ToLower(strings.TrimSpace(host)) || !validDNSName(host) || host == "github.com" {
			return errors.New("asset redirect host is invalid")
		}
		if previous != "" && host <= previous {
			return errors.New("asset redirect hosts must be sorted and unique")
		}
		previous = host
	}
	return nil
}

func validReleaseAssetName(name string) bool {
	if name == "" || len(name) > 255 || path.Base(name) != name || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return false
	}
	for _, value := range name {
		if unicode.IsControl(value) || unicode.IsSpace(value) || !(unicode.IsLetter(value) || unicode.IsDigit(value) || strings.ContainsRune("._+-", value)) {
			return false
		}
	}
	return true
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, value := range label {
			if !((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-') {
				return false
			}
		}
	}
	return true
}

func validCommitSHA(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Package returns the exact package asset bound by this release.
func (release *VerifiedRelease) Package() (ReleaseAsset, error) {
	snapshot, err := release.trustSnapshot()
	if err != nil {
		return ReleaseAsset{}, err
	}
	name := fmt.Sprintf("rufusarm64_%s_arm64.deb", snapshot.metadata.ReleaseVersion)
	index := sort.Search(len(snapshot.metadata.Assets), func(index int) bool {
		return snapshot.metadata.Assets[index].Name >= name
	})
	if index >= len(snapshot.metadata.Assets) || snapshot.metadata.Assets[index].Name != name {
		return ReleaseAsset{}, fmt.Errorf("verified release does not contain %s", name)
	}
	return cloneReleaseAsset(snapshot.metadata.Assets[index]), nil
}

func (release *VerifiedRelease) trustSnapshot() (*releaseTrustSnapshot, error) {
	if release == nil || release.trusted == nil {
		return nil, errors.New("authenticated release metadata is required")
	}
	return release.trusted, nil
}

func cloneReleaseMetadata(metadata ReleaseMetadata) ReleaseMetadata {
	cloned := metadata
	cloned.Assets = make([]ReleaseAsset, len(metadata.Assets))
	for index, asset := range metadata.Assets {
		cloned.Assets[index] = cloneReleaseAsset(asset)
	}
	return cloned
}

func cloneReleaseAsset(asset ReleaseAsset) ReleaseAsset {
	cloned := asset
	cloned.RedirectHosts = append([]string(nil), asset.RedirectHosts...)
	return cloned
}

// EvaluateRelease refuses metadata rollback and release-version downgrade before
// reporting whether a newer authenticated package is available.
func EvaluateRelease(currentVersion string, minimumMetadataVersion int, release *VerifiedRelease) (UpdateDecision, error) {
	snapshot, err := release.trustSnapshot()
	if err != nil {
		return UpdateDecision{}, err
	}
	if minimumMetadataVersion < 0 {
		return UpdateDecision{}, errors.New("minimum metadata version cannot be negative")
	}
	if snapshot.metadata.Version < minimumMetadataVersion {
		return UpdateDecision{}, fmt.Errorf("release metadata rollback from accepted version %d to %d", minimumMetadataVersion, snapshot.metadata.Version)
	}
	current, err := parseReleaseVersion(currentVersion)
	if err != nil {
		return UpdateDecision{}, fmt.Errorf("current version: %w", err)
	}
	candidate, err := parseReleaseVersion(snapshot.metadata.ReleaseVersion)
	if err != nil {
		return UpdateDecision{}, fmt.Errorf("release version: %w", err)
	}
	comparison := compareVersionTriples(candidate, current)
	if comparison < 0 {
		return UpdateDecision{}, fmt.Errorf("release version downgrade from %s to %s", currentVersion, snapshot.metadata.ReleaseVersion)
	}
	packageAsset, err := release.Package()
	if err != nil {
		return UpdateDecision{}, err
	}
	return UpdateDecision{
		CurrentVersion: currentVersion, ReleaseVersion: snapshot.metadata.ReleaseVersion,
		MetadataVersion: snapshot.metadata.Version, UpdateAvailable: comparison > 0,
		Tag: snapshot.metadata.Tag, Commit: snapshot.metadata.Commit, Channel: snapshot.metadata.Channel,
		Package: packageAsset, MetadataSHA256: snapshot.sha256,
		SigningKeyIDs: append([]string(nil), snapshot.signingKeyIDs...),
	}, nil
}

// ReleaseDownloadResult binds the published package bytes back to the exact
// authenticated release metadata that authorized the transfer.
type ReleaseDownloadResult struct {
	ReleaseVersion  string         `json:"release_version"`
	MetadataVersion int            `json:"metadata_version"`
	MetadataSHA256  string         `json:"metadata_sha256"`
	Tag             string         `json:"tag"`
	Commit          string         `json:"commit"`
	SigningKeyIDs   []string       `json:"signing_key_ids"`
	Package         ReleaseAsset   `json:"package"`
	Download        DownloadResult `json:"download"`
}

// DownloadReleasePackage reuses the reviewed acquisition downloader for the
// exact ARM64 package bound by authenticated release metadata. It never installs
// the downloaded package or requests privilege.
func DownloadReleasePackage(ctx context.Context, release *VerifiedRelease, options DownloadOptions) (ReleaseDownloadResult, error) {
	snapshot, err := release.trustSnapshot()
	if err != nil {
		return ReleaseDownloadResult{}, err
	}
	packageAsset, err := release.Package()
	if err != nil {
		return ReleaseDownloadResult{}, err
	}
	image := Image{
		ID:            "rufusarm64-release",
		Name:          "RufusArm64 release package",
		Version:       snapshot.metadata.ReleaseVersion,
		Architecture:  "arm64",
		Filename:      packageAsset.Name,
		URL:           packageAsset.URL,
		SHA256:        packageAsset.SHA256,
		Size:          packageAsset.Size,
		RedirectHosts: append([]string(nil), packageAsset.RedirectHosts...),
	}
	download, err := Download(ctx, image, options)
	if err != nil {
		return ReleaseDownloadResult{}, fmt.Errorf("download authenticated release package: %w", err)
	}
	return ReleaseDownloadResult{
		ReleaseVersion:  snapshot.metadata.ReleaseVersion,
		MetadataVersion: snapshot.metadata.Version,
		MetadataSHA256:  snapshot.sha256,
		Tag:             snapshot.metadata.Tag,
		Commit:          snapshot.metadata.Commit,
		SigningKeyIDs:   append([]string(nil), snapshot.signingKeyIDs...),
		Package:         packageAsset,
		Download:        download,
	}, nil
}

type releaseVersion [3]uint64

func parseReleaseVersion(value string) (releaseVersion, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Count(value, ".") != 2 {
		return releaseVersion{}, errors.New("version must be strict MAJOR.MINOR.PATCH text")
	}
	parts := strings.Split(value, ".")
	var parsed releaseVersion
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return releaseVersion{}, errors.New("version components must be canonical decimal integers")
		}
		for _, value := range part {
			if value < '0' || value > '9' {
				return releaseVersion{}, errors.New("version components must be decimal integers")
			}
		}
		number, err := strconv.ParseUint(part, 10, 63)
		if err != nil {
			return releaseVersion{}, errors.New("version component is out of range")
		}
		parsed[index] = number
	}
	return parsed, nil
}

func compareVersionTriples(left, right releaseVersion) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}
