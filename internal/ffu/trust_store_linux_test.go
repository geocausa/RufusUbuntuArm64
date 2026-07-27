//go:build linux

package ffu

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type trustStoreTestFixture struct {
	bundle   []byte
	envelope []byte
	policy   TrustMetadataPolicy
}

func TestPublishAuthenticatedTrustBundleAndRecover(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	fixture := newTrustStoreTestFixture(t, 7)

	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveTrustStoreResult(t, published)
	if published.Reused || published.PreviousGeneration != "" {
		t.Fatalf("unexpected first publication result: %#v", published)
	}
	assertTrustStoreLayout(t, root, 1)
	for _, name := range []string{trustStoreBundleName, trustStoreEnvelopeName, trustStoreEvidenceName} {
		info, err := os.Stat(filepath.Join(root, trustStoreGenerationsName, published.Generation, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}

	later := trustMetadataEvaluationTime.Add(24 * time.Hour)
	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, later, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveTrustStoreResult(t, recovered)
	if !recovered.Reused || recovered.Active != published.Active || recovered.Plan.Authentication.EvaluationTime != later.UTC().Format(time.RFC3339) {
		t.Fatalf("unexpected recovery result: %#v", recovered)
	}

	reused, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, later, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reused.Reused || reused.Active != published.Active || reused.Generation != published.Generation {
		t.Fatalf("same generation was not reused: %#v", reused)
	}
	assertTrustStoreLayout(t, root, 1)
}

func TestPublishAuthenticatedTrustBundleUpdatesAtomicActiveRecord(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	first := newTrustStoreTestFixture(t, 7)
	second := newTrustStoreTestFixtureWithPolicy(t, 8, first.policy)

	one, err := PublishAuthenticatedTrustBundle(context.Background(), root, first.bundle, first.envelope, first.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	two, err := PublishAuthenticatedTrustBundle(context.Background(), root, second.bundle, second.envelope, second.policy, trustMetadataEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if two.PreviousGeneration != one.Generation || two.Generation == one.Generation || two.Active.Sequence != 8 {
		t.Fatalf("unexpected update result: first=%#v second=%#v", one, two)
	}
	assertTrustStoreLayout(t, root, 2)

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, second.policy, trustMetadataEvaluationTime.Add(2*time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Generation != two.Generation || recovered.Active.Sequence != 8 {
		t.Fatalf("recovered wrong generation: %#v", recovered)
	}
	if _, err := os.Stat(filepath.Join(root, trustStoreGenerationsName, one.Generation)); err != nil {
		t.Fatalf("previous immutable generation was not retained: %v", err)
	}
}

func TestPublishAuthenticatedTrustBundleRollsBackEveryFirstPublicationStage(t *testing.T) {
	stages := []string{
		"validated", "generation-created", "bundle-staged", "metadata-staged", "evidence-staged",
		"generation-synced", "generation-published", "active-staged", "active-committed", "verified",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root := newTrustStoreTestRoot(t)
			fixture := newTrustStoreTestFixture(t, 7)
			_, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("stage %s error=%v", stage, err)
			}
			if _, statErr := os.Lstat(filepath.Join(root, trustStoreActiveName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("active record survived failed first publication: %v", statErr)
			}
			assertTrustStoreLayout(t, root, 0)
		})
	}
}

func TestPublishAuthenticatedTrustBundleRollsBackEveryUpdateStage(t *testing.T) {
	stages := []string{
		"validated", "generation-created", "bundle-staged", "metadata-staged", "evidence-staged",
		"generation-synced", "generation-published", "active-staged", "active-committed", "verified",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root := newTrustStoreTestRoot(t)
			first := newTrustStoreTestFixture(t, 7)
			second := newTrustStoreTestFixtureWithPolicy(t, 8, first.policy)
			original, err := PublishAuthenticatedTrustBundle(context.Background(), root, first.bundle, first.envelope, first.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = PublishAuthenticatedTrustBundle(context.Background(), root, second.bundle, second.envelope, second.policy, trustMetadataEvaluationTime.Add(time.Hour), TrustStoreOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("stage %s error=%v", stage, err)
			}
			recovered, recoverErr := RecoverAuthenticatedTrustBundle(context.Background(), root, first.policy, trustMetadataEvaluationTime.Add(2*time.Hour), TrustStoreOptions{})
			if recoverErr != nil {
				t.Fatal(recoverErr)
			}
			if recovered.Active != original.Active || recovered.Generation != original.Generation {
				t.Fatalf("failed update changed active generation: original=%#v recovered=%#v", original, recovered)
			}
			assertTrustStoreLayout(t, root, 1)
		})
	}
}

func TestRecoverAuthenticatedTrustBundleCleansKnownTemporaries(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	fixture := newTrustStoreTestFixture(t, 7)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, trustStoreTempActive+"0123456789abcdef01234567"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	tempGeneration := filepath.Join(root, trustStoreGenerationsName, trustStoreTempGeneration+"0123456789abcdef01234567")
	if err := os.Mkdir(tempGeneration, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempGeneration, trustStoreBundleName), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Generation != published.Generation {
		t.Fatalf("recovery changed generation: %#v", recovered)
	}
	assertNoTrustStoreTemporaries(t, root)
}

func TestRecoverAuthenticatedTrustBundleRejectsTamperingAndUnsafeLayout(t *testing.T) {
	t.Run("bundle changed", func(t *testing.T) {
		root, fixture, published := publishedTrustStoreTestFixture(t)
		generationPath := filepath.Join(root, trustStoreGenerationsName, published.Generation)
		makeTrustStoreTreeWritableForTest(t, generationPath)
		path := filepath.Join(generationPath, trustStoreBundleName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		sealTrustStoreGenerationForTest(t, generationPath)
		if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "digests") {
			t.Fatalf("tampered bundle error=%v", err)
		}
	})

	t.Run("active hard link", func(t *testing.T) {
		root, fixture, _ := publishedTrustStoreTestFixture(t)
		active := filepath.Join(root, trustStoreActiveName)
		if err := os.Link(active, filepath.Join(root, trustStoreTempActive+"0123456789abcdef01234567")); err != nil {
			t.Fatal(err)
		}
		if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "hard-link") {
			t.Fatalf("hard-linked active error=%v", err)
		}
	})

	t.Run("unexpected generation entry", func(t *testing.T) {
		root, fixture, published := publishedTrustStoreTestFixture(t)
		generationPath := filepath.Join(root, trustStoreGenerationsName, published.Generation)
		makeTrustStoreTreeWritableForTest(t, generationPath)
		if err := os.WriteFile(filepath.Join(generationPath, "extra"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		sealTrustStoreGenerationForTest(t, generationPath)
		if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "unexpected") {
			t.Fatalf("unexpected entry error=%v", err)
		}
	})

	t.Run("group writable root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o770); err != nil {
			t.Fatal(err)
		}
		fixture := newTrustStoreTestFixture(t, 7)
		if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("group-writable root error=%v", err)
		}
	})

	t.Run("symlink root", func(t *testing.T) {
		parent := t.TempDir()
		realRoot := filepath.Join(parent, "real")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(realRoot, link); err != nil {
			t.Fatal(err)
		}
		fixture := newTrustStoreTestFixture(t, 7)
		if _, err := PublishAuthenticatedTrustBundle(context.Background(), link, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "symbolic links") {
			t.Fatalf("symlink root error=%v", err)
		}
	})
}

func TestPublishAuthenticatedTrustBundleDetectsRootPathSubstitution(t *testing.T) {
	parent := t.TempDir()
	registerTrustStoreTestCleanup(t, parent)
	root := filepath.Join(parent, "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newTrustStoreTestFixture(t, 7)
	moved := root + ".moved"
	_, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{hook: func(stage string) error {
		if stage != "active-committed" {
			return nil
		}
		if err := os.Rename(root, moved); err != nil {
			return err
		}
		return os.Mkdir(root, 0o700)
	}})
	if err == nil || !strings.Contains(err.Error(), "substituted") {
		t.Fatalf("root substitution error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(moved, trustStoreActiveName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rollback did not remove active record from original descriptor: %v", statErr)
	}
}

func TestPublishAuthenticatedTrustBundleDetectsGenerationsPathSubstitution(t *testing.T) {
	parent := t.TempDir()
	registerTrustStoreTestCleanup(t, parent)
	root := filepath.Join(parent, "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newTrustStoreTestFixture(t, 7)
	generations := filepath.Join(root, trustStoreGenerationsName)
	moved := generations + ".moved"
	_, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{hook: func(stage string) error {
		if stage != "generation-published" {
			return nil
		}
		if err := os.Rename(generations, moved); err != nil {
			return err
		}
		return os.Mkdir(generations, 0o700)
	}})
	if err == nil || !strings.Contains(err.Error(), "substituted") {
		t.Fatalf("generations substitution error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, trustStoreActiveName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("active record appeared after generations substitution: %v", statErr)
	}
	entries, readErr := os.ReadDir(moved)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("rollback did not remove generation from original descriptor: %v", entries)
	}
}

func TestPublishAuthenticatedTrustBundleRejectsActiveMutationBeforeCommit(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	first := newTrustStoreTestFixture(t, 7)
	second := newTrustStoreTestFixtureWithPolicy(t, 8, first.policy)
	original, err := PublishAuthenticatedTrustBundle(context.Background(), root, first.bundle, first.envelope, first.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mutated := original.Active
	mutated.EvidenceSHA256 = strings.Repeat("0", 64)
	mutatedData, marshalErr := json.Marshal(mutated)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	_, err = PublishAuthenticatedTrustBundle(context.Background(), root, second.bundle, second.envelope, second.policy, trustMetadataEvaluationTime.Add(time.Hour), TrustStoreOptions{hook: func(stage string) error {
		if stage != "generation-published" {
			return nil
		}
		return os.WriteFile(filepath.Join(root, trustStoreActiveName), mutatedData, 0o600)
	}})
	if err == nil || !strings.Contains(err.Error(), "changed before commit") {
		t.Fatalf("active mutation error=%v", err)
	}
	assertTrustStoreLayout(t, root, 1)
	if _, statErr := os.Stat(filepath.Join(root, trustStoreGenerationsName, original.Generation)); statErr != nil {
		t.Fatalf("previous generation was removed after active mutation: %v", statErr)
	}
}

func TestPublishAuthenticatedTrustBundleRespectsContextAndLock(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	fixture := newTrustStoreTestFixture(t, 7)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PublishAuthenticatedTrustBundle(ctx, root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}

	midContext, midCancel := context.WithCancel(context.Background())
	if _, err := PublishAuthenticatedTrustBundle(midContext, root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{hook: func(stage string) error {
		if stage == "metadata-staged" {
			midCancel()
		}
		return nil
	}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-transaction cancellation error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, trustStoreActiveName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active record survived cancellation: %v", err)
	}
	assertTrustStoreLayout(t, root, 0)

	file, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("competing lock error=%v", err)
	}
}

func TestTrustStoreCanonicalRecordsRejectDuplicateMembers(t *testing.T) {
	var record TrustStoreActiveRecord
	data := []byte(`{"schema":1,"schema":1,"purpose":"ffu-trust-bundle-active"}`)
	if _, err := decodeCanonicalTrustStoreJSON(data, &record, "active"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate record error=%v", err)
	}
}

func FuzzDecodeCanonicalTrustStoreJSONDoesNotPanic(f *testing.F) {
	f.Add([]byte(`{"schema":1,"purpose":"ffu-trust-bundle-active"}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var record TrustStoreActiveRecord
		_, _ = decodeCanonicalTrustStoreJSON(data, &record, "active")
	})
}

func newTrustStoreTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	registerTrustStoreTestCleanup(t, root)
	return root
}

func registerTrustStoreTestCleanup(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		if err := makeTrustStoreTreeWritable(root); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("prepare trust-store fixture for cleanup: %v", err)
		}
	})
}

func makeTrustStoreTreeWritableForTest(t *testing.T, root string) {
	t.Helper()
	if err := makeTrustStoreTreeWritable(root); err != nil {
		t.Fatal(err)
	}
}

func makeTrustStoreTreeWritable(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		mode := fs.FileMode(0o600)
		if entry.IsDir() {
			mode = 0o700
		}
		return os.Chmod(path, mode)
	})
}

func sealTrustStoreGenerationForTest(t *testing.T, generationPath string) {
	t.Helper()
	entries, err := os.ReadDir(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected test generation directory %q", entry.Name())
		}
		if err := os.Chmod(filepath.Join(generationPath, entry.Name()), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(generationPath, 0o500); err != nil {
		t.Fatal(err)
	}
}

func newTrustStoreTestFixture(t *testing.T, sequence uint64) trustStoreTestFixture {
	t.Helper()
	policy, keys := trustMetadataTestPolicy(t, 3, 2)
	return newTrustStoreTestFixtureWithKeys(t, sequence, policy, keys)
}

func newTrustStoreTestFixtureWithPolicy(t *testing.T, sequence uint64, policy TrustMetadataPolicy) trustStoreTestFixture {
	t.Helper()
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	return newTrustStoreTestFixtureWithKeys(t, sequence, policy, keys)
}

func newTrustStoreTestFixtureWithKeys(t *testing.T, sequence uint64, policy TrustMetadataPolicy, keys []trustMetadataTestKey) trustStoreTestFixture {
	t.Helper()
	document := validTrustBundleDocument(t)
	document.Sequence = sequence
	bundle := marshalTrustBundle(t, document)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:policy.Threshold], nil)
	return trustStoreTestFixture{bundle: bundle, envelope: envelope, policy: policy}
}

func publishedTrustStoreTestFixture(t *testing.T) (string, trustStoreTestFixture, TrustStoreResult) {
	t.Helper()
	root := newTrustStoreTestRoot(t)
	fixture := newTrustStoreTestFixture(t, 7)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return root, fixture, published
}

func assertInactiveTrustStoreResult(t *testing.T, result TrustStoreResult) {
	t.Helper()
	if result.Generation == "" || result.Active.Generation != result.Generation || result.Active.Sequence != result.Plan.Sequence {
		t.Fatalf("incomplete trust-store result: %#v", result)
	}
	if !result.Plan.BundleSignatureAuthenticated || result.Plan.Authentication == nil {
		t.Fatalf("published plan is not authenticated: %#v", result.Plan)
	}
	if result.Plan.TrustAnchorsActivated || result.Plan.HostTLSStoreConsulted || result.Plan.CertificateChainBuilt || result.Plan.PublisherTrusted {
		t.Fatalf("publication crossed inactive trust boundary: %#v", result.Plan)
	}
}

func assertTrustStoreLayout(t *testing.T, root string, expectedGenerations int) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), trustStoreTempActive) {
			t.Fatalf("temporary active record remains: %s", entry.Name())
		}
	}
	generationRoot := filepath.Join(root, trustStoreGenerationsName)
	generations, err := os.ReadDir(generationRoot)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range generations {
		if strings.HasPrefix(entry.Name(), trustStoreTempGeneration) {
			t.Fatalf("temporary generation remains: %s", entry.Name())
		}
		if validTrustStoreGenerationName(entry.Name()) {
			count++
		}
	}
	if count != expectedGenerations {
		t.Fatalf("generation count=%d want=%d entries=%v", count, expectedGenerations, generations)
	}
}

func assertNoTrustStoreTemporaries(t *testing.T, root string) {
	t.Helper()
	assertTrustStoreLayout(t, root, 1)
}

func TestTrustStoreEvidenceIsCanonicalAndInactive(t *testing.T) {
	root, _, published := publishedTrustStoreTestFixture(t)
	data, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, published.Generation, trustStoreEvidenceName))
	if err != nil {
		t.Fatal(err)
	}
	var evidence TrustStoreGenerationEvidence
	if _, err := decodeCanonicalTrustStoreJSON(data, &evidence, "evidence"); err != nil {
		t.Fatal(err)
	}
	if evidence.TrustAnchorsActivated || evidence.PublicationEvaluationTime != trustMetadataEvaluationTime.Format(time.RFC3339) {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	reencoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(data) {
		t.Fatal("evidence is not deterministic")
	}
}
