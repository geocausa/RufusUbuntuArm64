//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestActivateAuthenticatedTrustBundle(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	activeBefore, err := os.ReadFile(filepath.Join(root, trustStoreActiveName))
	if err != nil {
		t.Fatal(err)
	}
	generationBefore := trustActivationGenerationSnapshot(t, root, published.Generation)
	evaluationTime := trustMetadataEvaluationTime.Add(2 * time.Hour)

	activation, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, evaluationTime, TrustActivationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertActivatedTrustBundle(t, activation, published, evaluationTime)
	if len(activation.Roots) != 1 || len(activation.Roots[0].CertificateDER) == 0 {
		t.Fatalf("missing activated root material: %#v", activation.Roots)
	}
	digest := sha256.Sum256(activation.Roots[0].CertificateDER)
	if hex.EncodeToString(digest[:]) != activation.Roots[0].Anchor.CertificateSHA256 {
		t.Fatal("activated root DER does not match its authenticated fingerprint")
	}
	activeAfter, err := os.ReadFile(filepath.Join(root, trustStoreActiveName))
	if err != nil {
		t.Fatal(err)
	}
	if string(activeBefore) != string(activeAfter) {
		t.Fatal("activation rewrote the durable active record")
	}
	if after := trustActivationGenerationSnapshot(t, root, published.Generation); after != generationBefore {
		t.Fatalf("activation changed immutable generation: before=%q after=%q", generationBefore, after)
	}

	activation.Roots[0].CertificateDER[0] ^= 0xff
	again, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, evaluationTime, TrustActivationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	againDigest := sha256.Sum256(again.Roots[0].CertificateDER)
	if hex.EncodeToString(againDigest[:]) != again.Roots[0].Anchor.CertificateSHA256 {
		t.Fatal("caller mutation escaped into durable activated root material")
	}
	if again.ActivationSHA256 != activation.ActivationSHA256 {
		t.Fatal("activation evidence is not deterministic")
	}
}

func TestActivateAuthenticatedTrustBundleRejectsMissingWrongExpiredAndTamperedState(t *testing.T) {
	t.Run("missing publication", func(t *testing.T) {
		root := newTrustStoreTestRoot(t)
		fixture := newTrustStoreTestFixture(t, 7)
		_, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{})
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing publication error=%v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(root, trustStoreGenerationsName)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("read-only activation created storage: %v", statErr)
		}
	})

	t.Run("wrong policy", func(t *testing.T) {
		root, _, _ := publishedTrustStoreTestFixture(t)
		wrong, _ := trustMetadataTestPolicy(t, 2, 1)
		if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, wrong, trustMetadataEvaluationTime, TrustActivationOptions{}); err == nil || !(strings.Contains(err.Error(), "key-set") || strings.Contains(err.Error(), "threshold")) {
			t.Fatalf("wrong policy error=%v", err)
		}
	})

	t.Run("expired metadata", func(t *testing.T) {
		root, fixture, _ := publishedTrustStoreTestFixture(t)
		expired := time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)
		if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, expired, TrustActivationOptions{}); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired activation error=%v", err)
		}
	})

	t.Run("tampered bundle", func(t *testing.T) {
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
		if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{}); err == nil || !strings.Contains(err.Error(), "digests") {
			t.Fatalf("tampered activation error=%v", err)
		}
	})
}

func TestActivateAuthenticatedTrustBundleRejectsSubstitutionAndActiveMutation(t *testing.T) {
	t.Run("root substitution", func(t *testing.T) {
		parent := t.TempDir()
		registerTrustStoreTestCleanup(t, parent)
		root := filepath.Join(parent, "store")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		fixture := newTrustStoreTestFixture(t, 7)
		if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, fixture.bundle, fixture.envelope, fixture.policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err != nil {
			t.Fatal(err)
		}
		moved := root + ".moved"
		_, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{hook: func(stage string) error {
			if stage != "activation-planned" {
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
	})

	t.Run("active mutation", func(t *testing.T) {
		root, fixture, published := publishedTrustStoreTestFixture(t)
		mutated := published.Active
		mutated.EvidenceSHA256 = strings.Repeat("0", 64)
		mutatedData, err := json.Marshal(mutated)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{hook: func(stage string) error {
			if stage != "activation-planned" {
				return nil
			}
			return os.WriteFile(filepath.Join(root, trustStoreActiveName), mutatedData, 0o600)
		}})
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("active mutation error=%v", err)
		}
	})
}

func TestActivateAuthenticatedTrustBundleRespectsContextLockAndStages(t *testing.T) {
	root, fixture, _ := publishedTrustStoreTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ActivateAuthenticatedTrustBundle(ctx, root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled activation error=%v", err)
	}
	for _, stage := range []string{"recovered", "material-loaded", "activation-planned", "verified"} {
		t.Run(stage, func(t *testing.T) {
			_, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("stage %s error=%v", stage, err)
			}
		})
	}

	file, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{}); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("competing activation lock error=%v", err)
	}
}

func TestRequireActivatedTrustPlanRefusesLaterBoundaries(t *testing.T) {
	root, fixture, _ := publishedTrustStoreTestFixture(t)
	activation, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustMetadataEvaluationTime, TrustActivationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TrustBundlePlan){
		"host store": func(plan *TrustBundlePlan) { plan.HostTLSStoreConsulted = true },
		"chain":      func(plan *TrustBundlePlan) { plan.CertificateChainBuilt = true },
		"publisher":  func(plan *TrustBundlePlan) { plan.PublisherTrusted = true },
	} {
		t.Run(name, func(t *testing.T) {
			plan := activation.Plan
			mutate(&plan)
			if err := requireActivatedTrustPlan(plan); err == nil || !strings.Contains(err.Error(), "later") {
				t.Fatalf("later-boundary plan error=%v", err)
			}
		})
	}
}

func assertActivatedTrustBundle(t *testing.T, activation TrustBundleActivation, published TrustStoreResult, evaluationTime time.Time) {
	t.Helper()
	if activation.Schema != trustActivationSchema || activation.Purpose != trustActivationPurpose || activation.Generation != published.Generation || activation.Sequence != published.Active.Sequence || activation.BundleSHA256 != published.Active.BundleSHA256 {
		t.Fatalf("incomplete activation: %#v", activation)
	}
	if activation.PublicationPlanSHA256 != published.Active.PlanSHA256 || activation.PreActivationPlanSHA256 == "" || activation.ActivatedPlanSHA256 == "" || activation.ActivationSHA256 == "" {
		t.Fatalf("missing activation evidence: %#v", activation)
	}
	if activation.PreActivationPlanSHA256 == activation.ActivatedPlanSHA256 || activation.Plan.PlanSHA256 != activation.ActivatedPlanSHA256 {
		t.Fatalf("activation plan digest did not cross the boundary: %#v", activation)
	}
	if activation.ActivationEvaluationTime != evaluationTime.UTC().Format(time.RFC3339) || activation.Plan.EvaluationTime != evaluationTime.UTC().Format(time.RFC3339) {
		t.Fatalf("activation time mismatch: %#v", activation)
	}
	if err := requireActivatedTrustPlan(activation.Plan); err != nil {
		t.Fatal(err)
	}
	if activation.Authentication == nil || activation.Plan.Authentication == nil || activation.Authentication.MetadataSHA256 != activation.Plan.Authentication.MetadataSHA256 {
		t.Fatalf("activation authentication evidence mismatch: %#v", activation)
	}
	if activation.RootCount != len(activation.Roots) || activation.DistrustedCount != len(activation.DistrustedSHA256) {
		t.Fatalf("activation counts mismatch: %#v", activation)
	}
}

func trustActivationGenerationSnapshot(t *testing.T, root, generation string) string {
	t.Helper()
	generationPath := filepath.Join(root, trustStoreGenerationsName, generation)
	entries, err := os.ReadDir(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot strings.Builder
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(generationPath, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		_, _ = snapshot.WriteString(entry.Name())
		_, _ = snapshot.WriteString(":" + info.Mode().Perm().String() + ":" + hex.EncodeToString(digest[:]) + "\n")
	}
	return snapshot.String()
}

func TestActivateAuthenticatedTrustBundleRejectsNoncanonicalRootEncoding(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustMetadataTestPolicy(t, 3, 2)
	document := validTrustBundleDocument(t)
	encoded := document.Roots[0].CertificateDERBase64
	document.Roots[0].CertificateDERBase64 = encoded[:20] + "\n" + encoded[20:]
	bundle := marshalTrustBundle(t, document)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:policy.Threshold], nil)
	if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, bundle, envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{}); err != nil {
		t.Fatalf("publication should preserve the separately signed exact bytes: %v", err)
	}
	if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, policy, trustMetadataEvaluationTime, TrustActivationOptions{}); err == nil || !strings.Contains(err.Error(), "canonical padded base64") {
		t.Fatalf("noncanonical root activation error=%v", err)
	}
}

func FuzzDecodeActivatedTrustMaterialDoesNotPanic(f *testing.F) {
	bundle := marshalTrustBundleForFuzz(validTrustBundleDocumentForFuzz())
	plan, err := ParseTrustBundleBytes(bundle, 0, trustEvaluationTime)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bundle)
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = decodeActivatedTrustMaterial(data, plan)
	})
}
