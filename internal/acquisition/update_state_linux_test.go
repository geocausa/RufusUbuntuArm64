//go:build linux

package acquisition

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func updateStateFixture(t *testing.T, rootVersion, metadataVersion int, releaseVersion string, now time.Time, commitByte byte) (*VerifiedRoot, *VerifiedRelease) {
	t.Helper()
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(rootVersion, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testReleaseMetadata(metadataVersion, releaseVersion, now)
	metadata.Commit = strings.Repeat(string([]byte{commitByte}), 40)
	release, err := VerifyReleaseMetadata(root, signedEnvelope(t, metadata, releaseSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	return root, release
}

func TestAcceptReleaseMetadataPersistsAndRejectsRollback(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "private", "state.json")
	root1, release1 := updateStateFixture(t, 1, 1, "0.16.0", now, 'a')
	accepted, err := AcceptReleaseMetadata(root1, release1, "0.15.0", UpdateStateOptions{Path: statePath, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Decision.UpdateAvailable || accepted.State.ReleaseMetadataVersion != 1 || accepted.State.RootVersion != 1 || accepted.StatePath != statePath {
		t.Fatalf("unexpected accepted state: %+v", accepted)
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Dir(statePath): 0o700,
		statePath:               0o600,
		statePath + ".lock":     0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s permissions = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}

	root2, release2 := updateStateFixture(t, 2, 2, "0.17.0", now.Add(time.Hour), 'b')
	accepted, err = AcceptReleaseMetadata(root2, release2, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State.RootVersion != 2 || accepted.State.ReleaseMetadataVersion != 2 || accepted.State.ReleaseVersion != "0.17.0" {
		t.Fatalf("state did not advance: %+v", accepted.State)
	}
	if _, err := AcceptReleaseMetadata(root1, release1, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(2 * time.Hour)}); err == nil || !strings.Contains(err.Error(), "root rollback") {
		t.Fatalf("root rollback error = %v", err)
	}
	_, substituted := updateStateFixture(t, 2, 2, "0.17.0", now.Add(time.Hour), 'c')
	if _, err := AcceptReleaseMetadata(root2, substituted, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(2 * time.Hour)}); err == nil || !strings.Contains(err.Error(), "changed without a version increase") {
		t.Fatalf("same-version substitution error = %v", err)
	}
	olderMetadata := cloneReleaseMetadata(release2.trusted.metadata)
	olderMetadata.Version = 3
	olderMetadata.ReleaseVersion = "0.16.0"
	olderMetadata.Tag = "v0.16.0"
	olderRelease := &VerifiedRelease{trusted: &releaseTrustSnapshot{
		metadata: olderMetadata, sha256: strings.Repeat("d", 64),
		signingKeyIDs: append([]string(nil), release2.trusted.signingKeyIDs...),
		rootVersion:   release2.trusted.rootVersion, rootSHA256: release2.trusted.rootSHA256,
	}}
	if _, err := AcceptReleaseMetadata(root2, olderRelease, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(2 * time.Hour)}); err == nil || !strings.Contains(err.Error(), "release version rollback") {
		t.Fatalf("release version rollback error = %v", err)
	}
}

func TestAcceptReleaseMetadataRejectsClockRollbackAndPreservesTime(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state", "state.json")
	root, release := updateStateFixture(t, 1, 1, "0.16.0", now, 'a')
	if _, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(-25 * time.Hour)}); err == nil || !strings.Contains(err.Error(), "system clock") {
		t.Fatalf("clock rollback error = %v", err)
	}
	accepted, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(-23 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State.AcceptedAt != now.Format(time.RFC3339) {
		t.Fatalf("accepted time moved backwards: %s", accepted.State.AcceptedAt)
	}
}

func TestUpdateStateRejectsSymlinksAndInsecureState(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	root, release := updateStateFixture(t, 1, 1, "0.16.0", now, 'a')
	directory := t.TempDir()
	stateDir := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "state.json")
	if err := os.Symlink(outside, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err == nil {
		t.Fatal("state symlink was accepted")
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("outside state changed: %q, %v", content, err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, statePath+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("lock symlink error = %v", err)
	}
	if err := os.Remove(statePath + ".lock"); err != nil {
		t.Fatal(err)
	}
	insecure := UpdateState{Schema: UpdateStateSchema, RootVersion: 1, RootSHA256: strings.Repeat("a", 64), ReleaseMetadataVersion: 1, ReleaseMetadataSHA256: strings.Repeat("b", 64), ReleaseVersion: "0.16.0", AcceptedAt: now.Format(time.RFC3339)}
	data, err := json.Marshal(insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("insecure state error = %v", err)
	}
}

func TestAcceptReleaseMetadataSerializesConcurrentVersions(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state", "state.json")
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	lowMetadata := testReleaseMetadata(1, "0.16.0", now)
	highMetadata := testReleaseMetadata(2, "0.17.0", now.Add(time.Minute))
	low, err := VerifyReleaseMetadata(root, signedEnvelope(t, lowMetadata, releaseSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	high, err := VerifyReleaseMetadata(root, signedEnvelope(t, highMetadata, releaseSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, release := range []*VerifiedRelease{low, high} {
		wait.Add(1)
		go func(candidate *VerifiedRelease) {
			defer wait.Done()
			<-start
			_, err := AcceptReleaseMetadata(root, candidate, "0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(time.Hour)})
			errorsSeen <- err
		}(release)
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	failureCount := 0
	for err := range errorsSeen {
		if err != nil {
			if !strings.Contains(err.Error(), "rollback") {
				t.Fatalf("unexpected concurrent error: %v", err)
			}
			failureCount++
		}
	}
	if failureCount > 1 {
		t.Fatalf("too many concurrent failures: %d", failureCount)
	}
	state, exists, err := loadUpdateState(statePath)
	if err != nil || !exists {
		t.Fatalf("load final state: %+v, %v", state, err)
	}
	if state.ReleaseMetadataVersion != 2 || state.ReleaseVersion != "0.17.0" {
		t.Fatalf("concurrent state regressed: %+v", state)
	}
}

func TestRootAndReleaseVerificationIgnoreExportedRootMutation(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	metadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, metadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	root.Metadata.Version = 999
	root.Metadata.Roles.Release = nil
	root.ExpiresAt = now.Add(-time.Hour)
	root.SHA256 = strings.Repeat("0", 64)
	releaseMetadata := testReleaseMetadata(1, "0.16.0", now)
	release, err := VerifyReleaseMetadata(root, signedEnvelope(t, releaseMetadata, releaseSigner), now)
	if err != nil {
		t.Fatalf("root exported mutation affected release verification: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "state", "state.json")
	accepted, err := AcceptReleaseMetadata(root, release, "0.15.0", UpdateStateOptions{Path: statePath, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State.RootVersion != 1 || accepted.State.RootSHA256 == root.SHA256 {
		t.Fatalf("state followed mutable root fields: %+v", accepted.State)
	}
}

func TestAcceptReleaseMetadataRejectsDifferentRootBinding(t *testing.T) {
	now := time.Date(2026, 7, 30, 16, 0, 0, 0, time.UTC)
	root1, release1 := updateStateFixture(t, 1, 1, "0.16.0", now, 'a')
	root2, _ := updateStateFixture(t, 2, 2, "0.17.0", now.Add(time.Hour), 'b')
	if _, err := AcceptReleaseMetadata(root2, release1, "0.15.0", UpdateStateOptions{Path: filepath.Join(t.TempDir(), "state.json"), Now: now}); err == nil || !strings.Contains(err.Error(), "different trusted root") {
		t.Fatalf("cross-root release error = %v", err)
	}
	if _, err := AcceptReleaseMetadata(root1, release1, "0.15.0", UpdateStateOptions{Path: filepath.Join(t.TempDir(), "state.json"), Now: now}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveUpdateStatePath(t *testing.T) {
	stateHome := filepath.Join(t.TempDir(), "state-home")
	t.Setenv("XDG_STATE_HOME", stateHome)
	path, err := ResolveUpdateStatePath("")
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(stateHome, "rufusarm64", "update", "state.json")
	if path != expected {
		t.Fatalf("default update state path = %q, want %q", path, expected)
	}
	t.Setenv("XDG_STATE_HOME", "relative")
	if _, err := ResolveUpdateStatePath(""); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative XDG state error = %v", err)
	}
}
