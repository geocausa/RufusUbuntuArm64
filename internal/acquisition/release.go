package acquisition

import (
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
	verified.SigningKeyIDs = keyIDs
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
	if release == nil {
		return ReleaseAsset{}, errors.New("verified release is required")
	}
	name := fmt.Sprintf("rufusarm64_%s_arm64.deb", release.Metadata.ReleaseVersion)
	index := sort.Search(len(release.Metadata.Assets), func(index int) bool {
		return release.Metadata.Assets[index].Name >= name
	})
	if index >= len(release.Metadata.Assets) || release.Metadata.Assets[index].Name != name {
		return ReleaseAsset{}, fmt.Errorf("verified release does not contain %s", name)
	}
	return release.Metadata.Assets[index], nil
}

// EvaluateRelease refuses metadata rollback and release-version downgrade before
// reporting whether a newer authenticated package is available.
func EvaluateRelease(currentVersion string, minimumMetadataVersion int, release *VerifiedRelease) (UpdateDecision, error) {
	if release == nil {
		return UpdateDecision{}, errors.New("verified release is required")
	}
	if minimumMetadataVersion < 0 {
		return UpdateDecision{}, errors.New("minimum metadata version cannot be negative")
	}
	if release.Metadata.Version < minimumMetadataVersion {
		return UpdateDecision{}, fmt.Errorf("release metadata rollback from accepted version %d to %d", minimumMetadataVersion, release.Metadata.Version)
	}
	current, err := parseReleaseVersion(currentVersion)
	if err != nil {
		return UpdateDecision{}, fmt.Errorf("current version: %w", err)
	}
	candidate, err := parseReleaseVersion(release.Metadata.ReleaseVersion)
	if err != nil {
		return UpdateDecision{}, fmt.Errorf("release version: %w", err)
	}
	comparison := compareVersionTriples(candidate, current)
	if comparison < 0 {
		return UpdateDecision{}, fmt.Errorf("release version downgrade from %s to %s", currentVersion, release.Metadata.ReleaseVersion)
	}
	packageAsset, err := release.Package()
	if err != nil {
		return UpdateDecision{}, err
	}
	return UpdateDecision{
		CurrentVersion: currentVersion, ReleaseVersion: release.Metadata.ReleaseVersion,
		MetadataVersion: release.Metadata.Version, UpdateAvailable: comparison > 0,
		Tag: release.Metadata.Tag, Commit: release.Metadata.Commit, Channel: release.Metadata.Channel,
		Package: packageAsset, MetadataSHA256: release.SHA256,
		SigningKeyIDs: append([]string(nil), release.SigningKeyIDs...),
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
