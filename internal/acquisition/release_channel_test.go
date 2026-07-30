package acquisition

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedReleaseEnvelope(t *testing.T, root *VerifiedRoot, metadata ReleaseMetadata, signer testTrustSigner, now time.Time) []byte {
	t.Helper()
	payload, _, err := CanonicalizeReleaseDraft(root, mustMarshal(t, metadata), now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{{KeyID: signer.id, Signature: ed25519.Sign(signer.private, payload)}})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func writeReleaseChannelFixture(t *testing.T, directory, serverURL string, bootstrap []byte, enabled bool) string {
	t.Helper()
	configDirectory := filepath.Join(directory, "package")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDirectory, "1.root.json"), bootstrap, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	config := ChannelConfig{
		Schema: ChannelConfigSchema, Enabled: enabled, BootstrapRoot: "1.root.json",
		RootURL: serverURL + "/root.{version}.json", CatalogURL: serverURL + "/catalog.json",
		ReleaseURL: serverURL + "/release.json", AllowedHosts: []string{parsed.Hostname()},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "channel.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRefreshReleaseChannelCachesAcceptsAndFallsBack(t *testing.T) {
	now := time.Date(2026, 7, 30, 15, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	root, err := VerifyBootstrapRoot(rootEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	releaseMetadata := testReleaseMetadata(3, "0.16.0", now)
	fixture := &channelFixture{release: signedReleaseEnvelope(t, root, releaseMetadata, releaseSigner, now)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	directory := t.TempDir()
	configPath := writeReleaseChannelFixture(t, directory, server.URL, rootEnvelope, true)
	cacheDir := filepath.Join(directory, "cache")
	statePath := filepath.Join(directory, "state", "state.json")
	options := ReleaseChannelOptions{CacheDir: cacheDir, StatePath: statePath, Now: now, AllowLoopback: true, HTTPClient: server.Client(), AllowCachedOnNetworkError: true}
	result, err := RefreshReleaseChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.FromCache || result.RootVersion != 1 || result.ReleaseMetadataVersion != 3 || result.ReleaseVersion != "0.16.0" || result.Package.Name != "rufusarm64_0.16.0_arm64.deb" {
		t.Fatalf("unexpected release channel result: %+v", result)
	}
	if _, err := result.Accept("0.15.0", UpdateStateOptions{Path: filepath.Join(directory, "other-state.json"), Now: now}); err == nil || !strings.Contains(err.Error(), "state checked during refresh") {
		t.Fatalf("cross-state acceptance error = %v", err)
	}
	if _, err := result.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(8 * 24 * time.Hour)}); err == nil || !strings.Contains(err.Error(), "release metadata version 3 has expired") {
		t.Fatalf("delayed acceptance expiry error = %v", err)
	}
	result.CacheDir = filepath.Join(directory, "forged-cache")
	result.RollbackStatePath = filepath.Join(directory, "forged-state.json")
	accepted, err := result.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Decision.UpdateAvailable || accepted.State.ReleaseMetadataVersion != 3 || accepted.State.RootVersion != 1 {
		t.Fatalf("unexpected accepted release: %+v", accepted)
	}
	for _, path := range []string{filepath.Join(cacheDir, "release.json"), statePath, statePath + ".lock"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %o", path, info.Mode().Perm())
		}
	}
	server.Close()
	cached, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: cacheDir, StatePath: statePath, Now: now.Add(time.Hour), Offline: true, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if !cached.FromCache || cached.ReleaseSHA256 != result.ReleaseSHA256 {
		t.Fatalf("unexpected cached result: %+v", cached)
	}
	if _, err := cached.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshReleaseChannelRejectsRollbackAndSubstitution(t *testing.T) {
	now := time.Date(2026, 7, 30, 15, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	root, err := VerifyBootstrapRoot(rootEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testReleaseMetadata(3, "0.16.0", now)
	fixture := &channelFixture{release: signedReleaseEnvelope(t, root, metadata, releaseSigner, now)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeReleaseChannelFixture(t, directory, server.URL, rootEnvelope, true)
	cacheDir, statePath := filepath.Join(directory, "cache"), filepath.Join(directory, "state", "state.json")
	options := ReleaseChannelOptions{CacheDir: cacheDir, StatePath: statePath, Now: now, AllowLoopback: true, HTTPClient: server.Client()}
	result, err := RefreshReleaseChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err != nil {
		t.Fatal(err)
	}

	substituted := metadata
	substituted.Commit = strings.Repeat("b", 40)
	fixture.mu.Lock()
	fixture.release = signedReleaseEnvelope(t, root, substituted, releaseSigner, now)
	fixture.mu.Unlock()
	options.Now = now.Add(time.Hour)
	if _, err := RefreshReleaseChannel(context.Background(), configPath, options); err == nil || !strings.Contains(err.Error(), "changed without a version increase") {
		t.Fatalf("same-version substitution error = %v", err)
	}

	rollback := testReleaseMetadata(2, "0.16.0", now)
	fixture.mu.Lock()
	fixture.release = signedReleaseEnvelope(t, root, rollback, releaseSigner, now)
	fixture.mu.Unlock()
	if _, err := RefreshReleaseChannel(context.Background(), configPath, options); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("metadata rollback error = %v", err)
	}
}

func TestRefreshReleaseChannelRootRotation(t *testing.T) {
	now := time.Date(2026, 7, 30, 15, 0, 0, 0, time.UTC)
	oldA, oldB := trustSigner(1), trustSigner(33)
	newA, newB := trustSigner(65), trustSigner(97)
	oldCatalog, newCatalog := trustSigner(129), trustSigner(161)
	oldRelease, newRelease := trustSigner(17), trustSigner(49)
	root1Metadata := releaseRootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldA, oldB}, []testTrustSigner{oldCatalog}, []testTrustSigner{oldRelease}, 1)
	root1Envelope := signedEnvelope(t, root1Metadata, oldA, oldB)
	root1, err := VerifyBootstrapRoot(root1Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	root2Metadata := releaseRootMetadata(2, now.Add(-time.Hour), now.Add(240*24*time.Hour), []testTrustSigner{newA, newB}, []testTrustSigner{newCatalog}, []testTrustSigner{newRelease}, 1)
	root2Envelope := signedEnvelope(t, root2Metadata, oldA, oldB, newA, newB)
	root2, err := VerifyRootUpdate(root1, root2Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &channelFixture{release: signedReleaseEnvelope(t, root1, testReleaseMetadata(1, "0.16.0", now), oldRelease, now)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeReleaseChannelFixture(t, directory, server.URL, root1Envelope, true)
	cacheDir, statePath := filepath.Join(directory, "cache"), filepath.Join(directory, "state", "state.json")
	options := ReleaseChannelOptions{CacheDir: cacheDir, StatePath: statePath, Now: now, AllowLoopback: true, HTTPClient: server.Client()}
	first, err := RefreshReleaseChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now}); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.roots = map[int][]byte{2: root2Envelope}
	fixture.release = signedReleaseEnvelope(t, root2, testReleaseMetadata(2, "0.17.0", now), newRelease, now)
	fixture.mu.Unlock()
	options.Now = now.Add(time.Hour)
	rotated, err := RefreshReleaseChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RootVersion != 2 || rotated.ReleaseVersion != "0.17.0" {
		t.Fatalf("unexpected rotated result: %+v", rotated)
	}
	if _, err := rotated.Accept("0.15.0", UpdateStateOptions{Path: statePath, Now: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "roots", "root.2.json")); err != nil {
		t.Fatalf("rotated root history missing: %v", err)
	}
}

func TestRefreshReleaseChannelRejectsMissingReleaseAndStateCollisions(t *testing.T) {
	now := time.Date(2026, 7, 30, 15, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	root, err := VerifyBootstrapRoot(rootEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &channelFixture{release: signedReleaseEnvelope(t, root, testReleaseMetadata(1, "0.16.0", now), releaseSigner, now)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeReleaseChannelFixture(t, directory, server.URL, rootEnvelope, true)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config ChannelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	config.ReleaseURL = ""
	data, _ = json.Marshal(config)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: filepath.Join(directory, "cache"), StatePath: filepath.Join(directory, "state.json"), Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "does not publish") {
		t.Fatalf("missing release URL error = %v", err)
	}
	config.ReleaseURL = server.URL + "/release.json"
	data, _ = json.Marshal(config)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(directory, "cache")
	if _, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: filepath.Dir(configPath), StatePath: filepath.Join(directory, "state.json"), Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("config/cache overlap error = %v", err)
	}
	if _, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: filepath.Join(filepath.Dir(configPath), "cache"), StatePath: filepath.Join(directory, "state.json"), Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("nested config/cache overlap error = %v", err)
	}
	if _, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: cacheDir, StatePath: filepath.Join(cacheDir, "state.json"), Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("cache/state collision error = %v", err)
	}
	if _, err := RefreshReleaseChannel(context.Background(), configPath, ReleaseChannelOptions{CacheDir: cacheDir, StatePath: configPath, Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("config/state collision error = %v", err)
	}
}
