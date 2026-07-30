//go:build linux

package acquisition

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

type releaseAssetFixture struct {
	directory string
	release   *VerifiedRelease
	tag       string
	commit    string
	files     map[string][]byte
}

func newReleaseAssetFixture(t *testing.T) releaseAssetFixture {
	t.Helper()
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	version := "0.16.0"
	tag := "v" + version
	commit := strings.Repeat("a", 40)
	files := map[string][]byte{
		"RufusArm64-0.16.0-source.zip": []byte("exact source archive"),
		"rufusarm64_0.16.0_arm64.deb":  []byte("exact Debian package"),
	}
	assets := make([]ReleaseAsset, 0, len(files))
	for name, data := range files {
		digest := sha256.Sum256(data)
		assets = append(assets, ReleaseAsset{
			Name: name, Size: uint64(len(data)), SHA256: hex.EncodeToString(digest[:]),
			URL: "https://github.com/geocausa/RufusUbuntuArm64/releases/download/" + tag + "/" + name,
		})
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })
	metadata := ReleaseMetadata{
		Type: "release", Schema: TrustSchemaVersion, Version: 4,
		Generated: now.Add(-time.Minute).Format(time.RFC3339), Expires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Product: "RufusArm64", Repository: "geocausa/RufusUbuntuArm64", ReleaseVersion: version,
		Tag: tag, Commit: commit, Channel: "stable", Assets: assets,
	}
	release, err := VerifyReleaseMetadata(root, signedEnvelope(t, metadata, releaseSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return releaseAssetFixture{directory: directory, release: release, tag: tag, commit: commit, files: files}
}

func TestVerifyReleaseAssetsExactGraph(t *testing.T) {
	fixture := newReleaseAssetFixture(t)
	result, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, data := range fixture.files {
		total += uint64(len(data))
	}
	if result.ReleaseVersion != "0.16.0" || result.MetadataVersion != 4 || result.Tag != fixture.tag || result.Commit != fixture.commit || result.Assets != len(fixture.files) || result.TotalBytes != total || len(result.SigningKeyIDs) != 1 {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestVerifyReleaseAssetsRejectsExpectedIdentityMismatch(t *testing.T) {
	fixture := newReleaseAssetFixture(t)
	if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, "v0.17.0", fixture.commit); err == nil || !strings.Contains(err.Error(), "expected tag") {
		t.Fatalf("tag mismatch error = %v", err)
	}
	if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, strings.Repeat("b", 40)); err == nil || !strings.Contains(err.Error(), "expected commit") {
		t.Fatalf("commit mismatch error = %v", err)
	}
	if _, err := VerifyReleaseAssets(&VerifiedRelease{}, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "authenticated release metadata") {
		t.Fatalf("unauthenticated release error = %v", err)
	}
}

func TestVerifyReleaseAssetsRejectsInventoryAndContentSubstitution(t *testing.T) {
	t.Run("extra file", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.directory, "unexpected"), []byte("extra"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "inventory mismatch") {
			t.Fatalf("extra file error = %v", err)
		}
	})
	t.Run("content", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		path := filepath.Join(fixture.directory, "rufusarm64_0.16.0_arm64.deb")
		if err := os.WriteFile(path, []byte("substituted package!"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || (!strings.Contains(err.Error(), "size mismatch") && !strings.Contains(err.Error(), "SHA-256 mismatch")) {
			t.Fatalf("content substitution error = %v", err)
		}
	})
}

func TestVerifyReleaseAssetsRejectsLinksAndMutablePermissions(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		name := "rufusarm64_0.16.0_arm64.deb"
		path := filepath.Join(fixture.directory, name)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "without following links") {
			t.Fatalf("symlink error = %v", err)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		path := filepath.Join(fixture.directory, "rufusarm64_0.16.0_arm64.deb")
		if err := os.Link(path, filepath.Join(t.TempDir(), "linked.deb")); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "single-link") {
			t.Fatalf("hardlink error = %v", err)
		}
	})
	t.Run("writable file", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		path := filepath.Join(fixture.directory, "rufusarm64_0.16.0_arm64.deb")
		if err := os.Chmod(path, 0o620); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "group/world writable") {
			t.Fatalf("writable file error = %v", err)
		}
	})
	t.Run("writable directory", func(t *testing.T) {
		fixture := newReleaseAssetFixture(t)
		if err := os.Chmod(fixture.directory, 0o720); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseAssets(fixture.release, fixture.directory, fixture.tag, fixture.commit); err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("writable directory error = %v", err)
		}
	})
}

func TestRecheckReleaseAssetDirectoryRejectsPermissionMutation(t *testing.T) {
	directory := t.TempDir()
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	var expected syscall.Stat_t
	if err := syscall.Fstat(fd, &expected); err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o720); err != nil {
		t.Fatal(err)
	}
	if err := recheckReleaseAssetDirectory(directory, expected, nil); err == nil || !strings.Contains(err.Error(), "directory changed") {
		t.Fatalf("directory permission mutation error = %v", err)
	}
}
