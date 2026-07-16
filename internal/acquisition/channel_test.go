package acquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type channelFixture struct {
	mu      sync.RWMutex
	roots   map[int][]byte
	catalog []byte
}

func (fixture *channelFixture) handler(writer http.ResponseWriter, request *http.Request) {
	fixture.mu.RLock()
	defer fixture.mu.RUnlock()
	writer.Header().Set("Content-Type", "application/json")
	if request.URL.Path == "/catalog.json" {
		_, _ = writer.Write(fixture.catalog)
		return
	}
	var version int
	if _, err := fmt.Sscanf(request.URL.Path, "/root.%d.json", &version); err == nil {
		if data, ok := fixture.roots[version]; ok {
			_, _ = writer.Write(data)
			return
		}
	}
	http.NotFound(writer, request)
}

func writeChannelFixture(t *testing.T, directory, serverURL string, bootstrap []byte, enabled bool) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "root.json"), bootstrap, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	config := ChannelConfig{
		Schema:        ChannelConfigSchema,
		Enabled:       enabled,
		BootstrapRoot: "root.json",
		RootURL:       serverURL + "/root.{version}.json",
		CatalogURL:    serverURL + "/catalog.json",
		AllowedHosts:  []string{parsed.Hostname()},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "channel.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRefreshChannelCachesAndRejectsRollback(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootMetadata := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	catalogV1 := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	fixture := &channelFixture{catalog: signedEnvelope(t, catalogV1, catalogSigner)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, server.URL, rootEnvelope, true)
	cacheDir := filepath.Join(directory, "cache")
	options := ChannelOptions{CacheDir: cacheDir, Now: now, AllowLoopback: true, HTTPClient: server.Client()}
	result, err := RefreshChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.CatalogVersion != 1 || result.RootVersion != 1 || result.FromCache {
		t.Fatalf("unexpected channel result: %+v", result)
	}
	stateInfo, err := os.Stat(filepath.Join(cacheDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o", stateInfo.Mode().Perm())
	}
	catalogV2 := channelCatalogMetadata(2, now, now.Add(7*24*time.Hour))
	fixture.mu.Lock()
	fixture.catalog = signedEnvelope(t, catalogV2, catalogSigner)
	fixture.mu.Unlock()
	result, err = RefreshChannel(context.Background(), configPath, options)
	if err != nil || result.CatalogVersion != 2 {
		t.Fatalf("catalog update result = %+v, %v", result, err)
	}
	fixture.mu.Lock()
	fixture.catalog = signedEnvelope(t, catalogV1, catalogSigner)
	fixture.mu.Unlock()
	if _, err := RefreshChannel(context.Background(), configPath, options); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("catalog rollback error = %v", err)
	}
}

func TestRefreshChannelRootRotationAndCachedFallback(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	oldA, oldB := trustSigner(1), trustSigner(33)
	newA, newB := trustSigner(65), trustSigner(97)
	oldCatalog, newCatalog := trustSigner(129), trustSigner(161)
	rootV1Metadata := rootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldA, oldB}, []testTrustSigner{oldCatalog})
	rootV1 := signedEnvelope(t, rootV1Metadata, oldA, oldB)
	rootV2Metadata := rootMetadata(2, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{newA, newB}, []testTrustSigner{newCatalog})
	rootV2 := signedEnvelope(t, rootV2Metadata, oldA, oldB, newA, newB)
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	fixture := &channelFixture{roots: map[int][]byte{2: rootV2}, catalog: signedEnvelope(t, catalog, newCatalog)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, server.URL, rootV1, true)
	cacheDir := filepath.Join(directory, "cache")
	options := ChannelOptions{
		CacheDir: cacheDir, Now: now, AllowLoopback: true, HTTPClient: server.Client(), AllowCachedOnNetworkError: true,
	}
	result, err := RefreshChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.RootVersion != 2 || result.SigningKeyIDs[0] != newCatalog.id {
		t.Fatalf("rotation result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "roots", "root.2.json")); err != nil {
		t.Fatalf("root history missing: %v", err)
	}
	server.Close()
	cached, err := RefreshChannel(context.Background(), configPath, options)
	if err != nil {
		t.Fatal(err)
	}
	if !cached.FromCache || cached.RootVersion != 2 || cached.CatalogVersion != 1 {
		t.Fatalf("cached result = %+v", cached)
	}
}

func TestRefreshChannelCatchesUpAcrossMultipleRootVersions(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	root1A, root1B := trustSigner(1), trustSigner(33)
	root2A, root2B := trustSigner(65), trustSigner(97)
	root3A, root3B := trustSigner(129), trustSigner(161)
	catalog1, catalog2, catalog3 := trustSigner(193), trustSigner(225), trustSigner(17)
	rootV1Metadata := rootMetadata(1, now.Add(-3*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{root1A, root1B}, []testTrustSigner{catalog1})
	rootV1 := signedEnvelope(t, rootV1Metadata, root1A, root1B)
	rootV2Metadata := rootMetadata(2, now.Add(-2*time.Hour), now.Add(240*24*time.Hour), []testTrustSigner{root2A, root2B}, []testTrustSigner{catalog2})
	rootV2 := signedEnvelope(t, rootV2Metadata, root1A, root1B, root2A, root2B)
	rootV3Metadata := rootMetadata(3, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{root3A, root3B}, []testTrustSigner{catalog3})
	rootV3 := signedEnvelope(t, rootV3Metadata, root2A, root2B, root3A, root3B)
	catalog := channelCatalogMetadata(7, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	fixture := &channelFixture{roots: map[int][]byte{2: rootV2, 3: rootV3}, catalog: signedEnvelope(t, catalog, catalog3)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, server.URL, rootV1, true)
	result, err := RefreshChannel(context.Background(), configPath, ChannelOptions{CacheDir: filepath.Join(directory, "cache"), Now: now, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if result.RootVersion != 3 || result.CatalogVersion != 7 || result.SigningKeyIDs[0] != catalog3.id {
		t.Fatalf("multi-root catch-up result = %+v", result)
	}
}

func TestChannelRejectsLargeClockRollback(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootMetadata := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	fixture := &channelFixture{catalog: signedEnvelope(t, catalog, catalogSigner)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, server.URL, rootEnvelope, true)
	cacheDir := filepath.Join(directory, "cache")
	options := ChannelOptions{CacheDir: cacheDir, Now: now, AllowLoopback: true, HTTPClient: server.Client(), AllowCachedOnNetworkError: true}
	if _, err := RefreshChannel(context.Background(), configPath, options); err != nil {
		t.Fatal(err)
	}
	server.Close()
	options.Now = now.Add(-25 * time.Hour)
	if _, err := RefreshChannel(context.Background(), configPath, options); err == nil || !strings.Contains(err.Error(), "system clock") {
		t.Fatalf("clock rollback error = %v", err)
	}
	options.Now = now.Add(-23 * time.Hour)
	if _, err := RefreshChannel(context.Background(), configPath, options); err != nil {
		t.Fatalf("bounded clock skew was rejected: %v", err)
	}
	state, exists, err := loadChannelState(filepath.Join(cacheDir, "state.json"))
	if err != nil || !exists || state.AcceptedAt != now.Format(time.RFC3339) {
		t.Fatalf("accepted time moved backwards: %+v, %v", state, err)
	}
}

func TestChannelRejectsDisabledConfigurationAndStateSymlink(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootMetadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	rootEnvelope := signedEnvelope(t, rootMetadata, rootA, rootB)
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, "https://downloads.example.com", rootEnvelope, false)
	if _, err := RefreshChannel(context.Background(), configPath, ChannelOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "not provisioned") {
		t.Fatalf("disabled channel error = %v", err)
	}
	cacheDir := filepath.Join(directory, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cacheDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	state := ChannelState{Schema: ChannelStateSchema, RootVersion: 1, RootSHA256: strings.Repeat("a", 64), CatalogVersion: 1, CatalogSHA256: strings.Repeat("b", 64), AcceptedAt: now.Format(time.RFC3339)}
	if err := storeChannelState(filepath.Join(cacheDir, "state.json"), state); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("state symlink error = %v", err)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("outside file changed: %q, %v", content, err)
	}
}

func TestChannelRejectsRootVersionSkipAndMalformedConfiguration(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	oldA, oldB := trustSigner(1), trustSigner(33)
	newA, newB := trustSigner(65), trustSigner(97)
	catalogSigner := trustSigner(129)
	rootV1Metadata := rootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldA, oldB}, []testTrustSigner{catalogSigner})
	rootV1 := signedEnvelope(t, rootV1Metadata, oldA, oldB)
	rootV3Metadata := rootMetadata(3, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{newA, newB}, []testTrustSigner{catalogSigner})
	rootV3 := signedEnvelope(t, rootV3Metadata, oldA, oldB, newA, newB)
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	fixture := &channelFixture{roots: map[int][]byte{2: rootV3}, catalog: signedEnvelope(t, catalog, catalogSigner)}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, server.URL, rootV1, true)
	if _, err := RefreshChannel(context.Background(), configPath, ChannelOptions{CacheDir: filepath.Join(directory, "cache"), Now: now, AllowLoopback: true, HTTPClient: server.Client()}); err == nil || !strings.Contains(err.Error(), "advance exactly") {
		t.Fatalf("root skip error = %v", err)
	}
	badTemplate := filepath.Join(directory, "bad-template.json")
	badConfig := ChannelConfig{Schema: 1, Enabled: true, BootstrapRoot: "root.json", RootURL: "https://root{version}.example.com/root.json", CatalogURL: "https://metadata.example.com/catalog.json", AllowedHosts: []string{"metadata.example.com"}}
	badData, _ := json.Marshal(badConfig)
	if err := os.WriteFile(badTemplate, badData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadChannelConfig(badTemplate, false); err == nil || !strings.Contains(err.Error(), "URL path") {
		t.Fatalf("root template placement error = %v", err)
	}

	malformed := filepath.Join(directory, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"schema":1,"schema":1,"enabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadChannelConfig(malformed, false); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate config key error = %v", err)
	}
}

func TestCachedRootHistoryRejectsSymlinkDirectory(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	root, err := VerifyBootstrapRoot(signedEnvelope(t, metadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	cacheDir := filepath.Join(directory, "cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside-roots")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cacheDir, "roots")); err != nil {
		t.Fatal(err)
	}
	if _, err := replayCachedRoots(root, cacheDir, now); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("root history symlink error = %v", err)
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("outside directory mode was changed through symlink: %o", info.Mode().Perm())
	}
}

func TestCachedRootHistoryReplaysExpiredIntermediate(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	root1A, root1B := trustSigner(1), trustSigner(33)
	root2A, root2B := trustSigner(65), trustSigner(97)
	root3A, root3B := trustSigner(129), trustSigner(161)
	catalog1, catalog2, catalog3 := trustSigner(193), trustSigner(225), trustSigner(17)
	rootV1Metadata := rootMetadata(1, now.Add(-400*24*time.Hour), now.Add(-200*24*time.Hour), []testTrustSigner{root1A, root1B}, []testTrustSigner{catalog1})
	rootV1 := signedEnvelope(t, rootV1Metadata, root1A, root1B)
	rootV2Metadata := rootMetadata(2, now.Add(-190*24*time.Hour), now.Add(-10*24*time.Hour), []testTrustSigner{root2A, root2B}, []testTrustSigner{catalog2})
	rootV2 := signedEnvelope(t, rootV2Metadata, root1A, root1B, root2A, root2B)
	rootV3Metadata := rootMetadata(3, now.Add(-9*24*time.Hour), now.Add(300*24*time.Hour), []testTrustSigner{root3A, root3B}, []testTrustSigner{catalog3})
	rootV3 := signedEnvelope(t, rootV3Metadata, root2A, root2B, root3A, root3B)
	catalog := channelCatalogMetadata(4, now.Add(-time.Hour), now.Add(7*24*time.Hour))
	catalogEnvelope := signedEnvelope(t, catalog, catalog3)

	directory := t.TempDir()
	configPath := filepath.Join(directory, "channel.json")
	if err := os.WriteFile(filepath.Join(directory, "root.json"), rootV1, 0o600); err != nil {
		t.Fatal(err)
	}
	config := ChannelConfig{Schema: 1, Enabled: true, BootstrapRoot: "root.json", RootURL: "https://metadata.example.com/root.{version}.json", CatalogURL: "https://metadata.example.com/catalog.json", AllowedHosts: []string{"metadata.example.com"}}
	configData, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(directory, "cache")
	if err := os.MkdirAll(filepath.Join(cacheDir, "roots"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "roots", "root.2.json"), rootV2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "roots", "root.3.json"), rootV3, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "catalog.json"), catalogEnvelope, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := RefreshChannel(context.Background(), configPath, ChannelOptions{CacheDir: cacheDir, Now: now, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.RootVersion != 3 || result.CatalogVersion != 4 || !result.FromCache {
		t.Fatalf("expired intermediate replay result = %+v", result)
	}
}
