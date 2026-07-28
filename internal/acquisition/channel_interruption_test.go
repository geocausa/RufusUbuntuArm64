package acquisition

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRefreshChannelRefusesStaleCatalogAfterRootPublicationInterruption(t *testing.T) {
	now := time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC)
	oldRootA, oldRootB := trustSigner(1), trustSigner(33)
	newRootA, newRootB := trustSigner(65), trustSigner(97)
	oldCatalog, newCatalog := trustSigner(129), trustSigner(161)

	rootV1Bytes := signedEnvelope(t,
		rootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldRootA, oldRootB}, []testTrustSigner{oldCatalog}),
		oldRootA, oldRootB,
	)
	rootV2Bytes := signedEnvelope(t,
		rootMetadata(2, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{newRootA, newRootB}, []testTrustSigner{newCatalog}),
		oldRootA, oldRootB, newRootA, newRootB,
	)
	catalogV1Bytes := signedEnvelope(t,
		channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour)),
		oldCatalog,
	)

	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, "https://downloads.example.com", rootV1Bytes, true)
	cacheDir := filepath.Join(directory, "cache")
	mustPrepareChannelCache(t, cacheDir)

	rootV1 := mustVerifyBootstrapRoot(t, rootV1Bytes, now)
	rootV2, err := VerifyRootUpdate(rootV1, rootV2Bytes, now)
	if err != nil {
		t.Fatal(err)
	}
	catalogV1 := mustVerifyChannelCatalog(t, rootV1, catalogV1Bytes, now)
	if err := storeRootHistory(cacheDir, rootV2, rootV2Bytes); err != nil {
		t.Fatal(err)
	}
	mustWritePrivateCacheFile(t, filepath.Join(cacheDir, "catalog.json"), catalogV1Bytes)
	mustStoreInterruptedChannelState(t, cacheDir, ChannelState{
		Schema: ChannelStateSchema, RootVersion: 1, RootSHA256: rootV1.SHA256,
		CatalogVersion: 1, CatalogSHA256: catalogV1.SHA256, AcceptedAt: now.Format(time.RFC3339),
	})
	statePath := filepath.Join(cacheDir, "state.json")
	before := mustReadFile(t, statePath)

	result, err := RefreshChannel(t.Context(), configPath, ChannelOptions{CacheDir: cacheDir, Now: now, Offline: true})
	if err == nil || result != nil {
		t.Fatalf("stale catalog under advanced root was accepted: result=%#v err=%v", result, err)
	}
	if !strings.Contains(err.Error(), "catalog") && !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("unexpected stale-catalog error: %v", err)
	}
	requireFileUnchanged(t, statePath, before)
}

func TestRefreshChannelRecoversForwardAfterCatalogPublicationInterruption(t *testing.T) {
	now := time.Date(2026, 7, 28, 2, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootBytes := signedEnvelope(t,
		rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}),
		rootA, rootB,
	)
	catalogV1Bytes := signedEnvelope(t,
		channelCatalogMetadata(1, now.Add(-2*time.Minute), now.Add(7*24*time.Hour)),
		catalogSigner,
	)
	catalogV2Bytes := signedEnvelope(t,
		channelCatalogMetadata(2, now.Add(-time.Minute), now.Add(7*24*time.Hour)),
		catalogSigner,
	)

	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, "https://downloads.example.com", rootBytes, true)
	cacheDir := filepath.Join(directory, "cache")
	mustPrepareChannelCache(t, cacheDir)
	root := mustVerifyBootstrapRoot(t, rootBytes, now)
	catalogV1 := mustVerifyChannelCatalog(t, root, catalogV1Bytes, now)
	catalogV2 := mustVerifyChannelCatalog(t, root, catalogV2Bytes, now)
	mustWritePrivateCacheFile(t, filepath.Join(cacheDir, "catalog.json"), catalogV2Bytes)
	mustStoreInterruptedChannelState(t, cacheDir, ChannelState{
		Schema: ChannelStateSchema, RootVersion: 1, RootSHA256: root.SHA256,
		CatalogVersion: 1, CatalogSHA256: catalogV1.SHA256, AcceptedAt: now.Format(time.RFC3339),
	})

	result, err := RefreshChannel(t.Context(), configPath, ChannelOptions{
		CacheDir: cacheDir, Now: now.Add(-time.Hour), Offline: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.FromCache || result.RootVersion != 1 || result.CatalogVersion != 2 || result.CatalogSHA256 != catalogV2.SHA256 {
		t.Fatalf("forward recovery result = %#v", result)
	}
	state, exists, err := loadChannelState(filepath.Join(cacheDir, "state.json"))
	if err != nil || !exists {
		t.Fatalf("load recovered state: exists=%v err=%v", exists, err)
	}
	if state.CatalogVersion != 2 || state.CatalogSHA256 != catalogV2.SHA256 || state.AcceptedAt != now.Format(time.RFC3339) {
		t.Fatalf("recovered accepted state = %#v", state)
	}
}

func TestRefreshChannelRefusesStateAheadOfCatalogAfterStatePublicationInterruption(t *testing.T) {
	now := time.Date(2026, 7, 28, 3, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootBytes := signedEnvelope(t,
		rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}),
		rootA, rootB,
	)
	catalogV1Bytes := signedEnvelope(t,
		channelCatalogMetadata(1, now.Add(-2*time.Minute), now.Add(7*24*time.Hour)),
		catalogSigner,
	)
	catalogV2Bytes := signedEnvelope(t,
		channelCatalogMetadata(2, now.Add(-time.Minute), now.Add(7*24*time.Hour)),
		catalogSigner,
	)

	directory := t.TempDir()
	configPath := writeChannelFixture(t, directory, "https://downloads.example.com", rootBytes, true)
	cacheDir := filepath.Join(directory, "cache")
	mustPrepareChannelCache(t, cacheDir)
	root := mustVerifyBootstrapRoot(t, rootBytes, now)
	catalogV2 := mustVerifyChannelCatalog(t, root, catalogV2Bytes, now)
	catalogPath := filepath.Join(cacheDir, "catalog.json")
	mustWritePrivateCacheFile(t, catalogPath, catalogV1Bytes)
	mustStoreInterruptedChannelState(t, cacheDir, ChannelState{
		Schema: ChannelStateSchema, RootVersion: 1, RootSHA256: root.SHA256,
		CatalogVersion: 2, CatalogSHA256: catalogV2.SHA256, AcceptedAt: now.Format(time.RFC3339),
	})
	statePath := filepath.Join(cacheDir, "state.json")
	stateBefore := mustReadFile(t, statePath)
	catalogBefore := mustReadFile(t, catalogPath)

	result, err := RefreshChannel(t.Context(), configPath, ChannelOptions{CacheDir: cacheDir, Now: now, Offline: true})
	if err == nil || result != nil || !strings.Contains(err.Error(), "catalog rollback") {
		t.Fatalf("state-ahead interruption was accepted: result=%#v err=%v", result, err)
	}
	requireFileUnchanged(t, statePath, stateBefore)
	requireFileUnchanged(t, catalogPath, catalogBefore)
}

func TestRefreshChannelRejectsTruncatedCacheWithoutRewritingState(t *testing.T) {
	now := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	rootBytes := signedEnvelope(t,
		rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}),
		rootA, rootB,
	)
	catalogBytes := signedEnvelope(t,
		channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour)),
		catalogSigner,
	)
	root := mustVerifyBootstrapRoot(t, rootBytes, now)
	catalog := mustVerifyChannelCatalog(t, root, catalogBytes, now)

	for _, test := range []struct {
		name      string
		cachePath func(string) string
		content   []byte
	}{
		{name: "root-history", cachePath: func(cacheDir string) string { return filepath.Join(cacheDir, "roots", "root.2.json") }, content: []byte(`{"signed":`)},
		{name: "catalog", cachePath: func(cacheDir string) string { return filepath.Join(cacheDir, "catalog.json") }, content: []byte(`{"signed":`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			configPath := writeChannelFixture(t, directory, "https://downloads.example.com", rootBytes, true)
			cacheDir := filepath.Join(directory, "cache")
			mustPrepareChannelCache(t, cacheDir)
			if test.name == "root-history" {
				mustWritePrivateCacheFile(t, filepath.Join(cacheDir, "catalog.json"), catalogBytes)
			}
			mustWritePrivateCacheFile(t, test.cachePath(cacheDir), test.content)
			mustStoreInterruptedChannelState(t, cacheDir, ChannelState{
				Schema: ChannelStateSchema, RootVersion: 1, RootSHA256: root.SHA256,
				CatalogVersion: 1, CatalogSHA256: catalog.SHA256, AcceptedAt: now.Format(time.RFC3339),
			})
			statePath := filepath.Join(cacheDir, "state.json")
			before := mustReadFile(t, statePath)

			result, err := RefreshChannel(t.Context(), configPath, ChannelOptions{CacheDir: cacheDir, Now: now, Offline: true})
			if err == nil || result != nil {
				t.Fatalf("truncated %s cache was accepted: result=%#v err=%v", test.name, result, err)
			}
			requireFileUnchanged(t, statePath, before)
		})
	}
}

func mustPrepareChannelCache(t *testing.T, cacheDir string) {
	t.Helper()
	if err := ensurePrivateDirectory(cacheDir); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(filepath.Join(cacheDir, "roots")); err != nil {
		t.Fatal(err)
	}
}

func mustVerifyBootstrapRoot(t *testing.T, data []byte, now time.Time) *VerifiedRoot {
	t.Helper()
	root, err := VerifyBootstrapRoot(data, now)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustVerifyChannelCatalog(t *testing.T, root *VerifiedRoot, data []byte, now time.Time) *VerifiedChannelCatalog {
	t.Helper()
	catalog, err := VerifyChannelCatalog(root, data, now)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func mustWritePrivateCacheFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustStoreInterruptedChannelState(t *testing.T, cacheDir string, state ChannelState) {
	t.Helper()
	if err := storeChannelState(filepath.Join(cacheDir, "state.json"), state); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireFileUnchanged(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual := mustReadFile(t, path)
	if string(actual) != string(expected) {
		t.Fatalf("%s changed after refused interrupted state", path)
	}
}
