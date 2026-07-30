//go:build linux

package acquisition

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ReleaseAssetVerification records the exact authenticated release and staged
// asset graph checked before or after publication.
type ReleaseAssetVerification struct {
	ReleaseVersion  string   `json:"release_version"`
	MetadataVersion int      `json:"metadata_version"`
	MetadataSHA256  string   `json:"metadata_sha256"`
	Tag             string   `json:"tag"`
	Commit          string   `json:"commit"`
	SigningKeyIDs   []string `json:"signing_key_ids"`
	AssetDirectory  string   `json:"asset_directory"`
	Assets          int      `json:"assets"`
	TotalBytes      uint64   `json:"total_bytes"`
}

type verifiedReleaseAssetFile struct {
	name string
	stat syscall.Stat_t
}

// VerifyReleaseAssets hashes an exact descriptor-rooted directory and requires
// every file to match the immutable asset graph in authenticated release
// metadata. It refuses extra files, links, mutable permissions, path replacement,
// tag/commit mismatch, and content changes while hashing.
func VerifyReleaseAssets(release *VerifiedRelease, assetDirectory, expectedTag, expectedCommit string) (ReleaseAssetVerification, error) {
	snapshot, err := release.trustSnapshot()
	if err != nil {
		return ReleaseAssetVerification{}, err
	}
	expectedTag = strings.TrimSpace(expectedTag)
	expectedCommit = strings.TrimSpace(expectedCommit)
	if expectedTag == "" || expectedTag != snapshot.metadata.Tag {
		return ReleaseAssetVerification{}, fmt.Errorf("authenticated release tag %q does not match expected tag %q", snapshot.metadata.Tag, expectedTag)
	}
	if !validCommitSHA(expectedCommit) || expectedCommit != snapshot.metadata.Commit {
		return ReleaseAssetVerification{}, fmt.Errorf("authenticated release commit %q does not match expected commit %q", snapshot.metadata.Commit, expectedCommit)
	}
	assetDirectory = strings.TrimSpace(assetDirectory)
	if assetDirectory == "" {
		return ReleaseAssetVerification{}, errors.New("release asset directory is required")
	}
	absolute, err := filepath.Abs(assetDirectory)
	if err != nil {
		return ReleaseAssetVerification{}, fmt.Errorf("resolve release asset directory: %w", err)
	}
	directoryFD, err := syscall.Open(absolute, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ReleaseAssetVerification{}, fmt.Errorf("open release asset directory without following links: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), absolute)
	if directory == nil {
		_ = syscall.Close(directoryFD)
		return ReleaseAssetVerification{}, errors.New("open release asset directory returned an invalid file handle")
	}
	defer directory.Close()
	var directoryStat syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryStat); err != nil {
		return ReleaseAssetVerification{}, fmt.Errorf("inspect release asset directory: %w", err)
	}
	if directoryStat.Mode&syscall.S_IFMT != syscall.S_IFDIR || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&0o022 != 0 {
		return ReleaseAssetVerification{}, errors.New("release asset directory must be a real owner-controlled directory that is not group/world writable")
	}

	entries, err := directory.ReadDir(-1)
	if err != nil {
		return ReleaseAssetVerification{}, fmt.Errorf("enumerate release asset directory: %w", err)
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		actualNames = append(actualNames, entry.Name())
	}
	sort.Strings(actualNames)
	expectedNames := make([]string, len(snapshot.metadata.Assets))
	for index, asset := range snapshot.metadata.Assets {
		expectedNames[index] = asset.Name
	}
	if strings.Join(actualNames, "\x00") != strings.Join(expectedNames, "\x00") {
		return ReleaseAssetVerification{}, fmt.Errorf("release asset inventory mismatch: expected %v, got %v", expectedNames, actualNames)
	}

	checked := make([]verifiedReleaseAssetFile, 0, len(snapshot.metadata.Assets))
	var total uint64
	for _, asset := range snapshot.metadata.Assets {
		info, digest, err := hashReleaseAssetAt(directoryFD, asset.Name)
		if err != nil {
			return ReleaseAssetVerification{}, err
		}
		if uint64(info.Size) != asset.Size {
			return ReleaseAssetVerification{}, fmt.Errorf("release asset size mismatch for %s: metadata=%d file=%d", asset.Name, asset.Size, info.Size)
		}
		if digest != asset.SHA256 {
			return ReleaseAssetVerification{}, fmt.Errorf("release asset SHA-256 mismatch for %s: metadata=%s file=%s", asset.Name, asset.SHA256, digest)
		}
		checked = append(checked, verifiedReleaseAssetFile{name: asset.Name, stat: info})
		total += asset.Size
	}
	for _, asset := range checked {
		current, err := inspectReleaseAssetAt(directoryFD, asset.name)
		if err != nil {
			return ReleaseAssetVerification{}, err
		}
		if !sameReleaseAssetStat(asset.stat, current) {
			return ReleaseAssetVerification{}, fmt.Errorf("release asset path changed after hashing: %s", asset.name)
		}
	}
	if err := recheckReleaseAssetDirectory(absolute, directoryStat, expectedNames); err != nil {
		return ReleaseAssetVerification{}, err
	}
	return ReleaseAssetVerification{
		ReleaseVersion: snapshot.metadata.ReleaseVersion, MetadataVersion: snapshot.metadata.Version,
		MetadataSHA256: snapshot.sha256, Tag: snapshot.metadata.Tag, Commit: snapshot.metadata.Commit,
		SigningKeyIDs: append([]string(nil), snapshot.signingKeyIDs...), AssetDirectory: absolute,
		Assets: len(snapshot.metadata.Assets), TotalBytes: total,
	}, nil
}

func hashReleaseAssetAt(directoryFD int, name string) (syscall.Stat_t, string, error) {
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return syscall.Stat_t{}, "", fmt.Errorf("open release asset %s without following links: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return syscall.Stat_t{}, "", fmt.Errorf("open release asset %s returned an invalid file handle", name)
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return syscall.Stat_t{}, "", fmt.Errorf("inspect release asset %s: %w", name, err)
	}
	if err := validateReleaseAssetFileStat(name, before); err != nil {
		return syscall.Stat_t{}, "", err
	}
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
		return syscall.Stat_t{}, "", fmt.Errorf("hash release asset %s: %w", name, err)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return syscall.Stat_t{}, "", fmt.Errorf("reinspect release asset %s: %w", name, err)
	}
	if !sameReleaseAssetStat(before, after) {
		return syscall.Stat_t{}, "", fmt.Errorf("release asset changed while hashing: %s", name)
	}
	return after, hex.EncodeToString(digest.Sum(nil)), nil
}

func inspectReleaseAssetAt(directoryFD int, name string) (syscall.Stat_t, error) {
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return syscall.Stat_t{}, fmt.Errorf("reopen release asset %s without following links: %w", name, err)
	}
	defer syscall.Close(fd)
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		return syscall.Stat_t{}, fmt.Errorf("reinspect release asset path %s: %w", name, err)
	}
	if err := validateReleaseAssetFileStat(name, info); err != nil {
		return syscall.Stat_t{}, err
	}
	return info, nil
}

func validateReleaseAssetFileStat(name string, info syscall.Stat_t) error {
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Nlink != 1 || info.Uid != uint32(os.Geteuid()) || info.Mode&0o022 != 0 || info.Size <= 0 {
		return fmt.Errorf("release asset must be a non-empty owner-controlled single-link regular file that is not group/world writable: %s", name)
	}
	return nil
}

func sameReleaseAssetStat(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Nlink == right.Nlink &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func recheckReleaseAssetDirectory(path string, expected syscall.Stat_t, expectedNames []string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("reopen release asset directory without following links: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("reopen release asset directory returned an invalid file handle")
	}
	defer file.Close()
	var current syscall.Stat_t
	if err := syscall.Fstat(fd, &current); err != nil {
		return fmt.Errorf("reinspect release asset directory: %w", err)
	}
	if current.Mode&syscall.S_IFMT != syscall.S_IFDIR || !sameReleaseAssetStat(expected, current) {
		return errors.New("release asset directory changed during verification")
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("reenumerate release asset directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if strings.Join(names, "\x00") != strings.Join(expectedNames, "\x00") {
		return errors.New("release asset inventory changed during verification")
	}
	return nil
}
