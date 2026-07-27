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
	"testing"
	"time"
)

func TestApplyAuthenticatedTrustBundleWithdrawalAndRecover(t *testing.T) {
	root, policy, keys, published, operation, distrust := newTrustWithdrawalTestFixture(t)

	withdrawal, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustWithdrawalResult(t, withdrawal, published, distrust)
	assertTrustStoreLayout(t, root, 2)

	activeData := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
	var active TrustStoreActiveRecord
	if err := json.Unmarshal(activeData, &active); err != nil {
		t.Fatal(err)
	}
	if active.Purpose != trustStoreWithdrawnPurpose {
		t.Fatalf("active purpose=%q", active.Purpose)
	}

	recovered, err := RecoverAuthenticatedTrustBundleWithdrawal(context.Background(), root, policy, trustUpdateEvaluationTime.AddDate(1, 0, 0), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustWithdrawalResult(t, recovered, published, distrust)
	wrongPolicy, _ := trustUpdateTestPolicy(0x71, policy.Version, 3, 2)
	if _, err := RecoverAuthenticatedTrustBundleWithdrawal(context.Background(), root, wrongPolicy, trustUpdateEvaluationTime, TrustStoreOptions{}); err == nil {
		t.Fatal("wrong withdrawal policy was accepted")
	}

	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime, TrustStoreOptions{}); !errors.Is(err, ErrTrustBundleWithdrawn) {
		t.Fatalf("ordinary recovery error=%v", err)
	}
	if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime, TrustActivationOptions{}); !errors.Is(err, ErrTrustBundleWithdrawn) {
		t.Fatalf("activation error=%v", err)
	}
	republishDocument := validTrustBundleDocument(t)
	republishDocument.Sequence = withdrawal.Active.Sequence + 1
	republishBundle := marshalTrustBundle(t, republishDocument)
	republishMetadata := trustMetadataEnvelope(t, republishBundle, policy, keys[:policy.Threshold], nil)
	if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, republishBundle, republishMetadata, policy, trustUpdateEvaluationTime, TrustStoreOptions{}); !errors.Is(err, ErrTrustBundleWithdrawn) {
		t.Fatalf("unsigned re-publication bypass error=%v", err)
	}
}

func TestApplyAuthenticatedTrustBundleWithdrawalRollsBackEveryStage(t *testing.T) {
	stages := []string{
		"authorized",
		"generation-created",
		"bundle-staged",
		"metadata-staged",
		"evidence-staged",
		"generation-synced",
		"generation-published",
		"active-staged",
		"active-committed",
		"verified",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root, policy, _, published, operation, _ := newTrustWithdrawalTestFixture(t)
			before := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
			_, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{hook: func(got string) error {
				if got == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("error=%v", err)
			}
			after := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
			if string(after) != string(before) {
				t.Fatal("rollback did not restore the previous active record")
			}
			recovered, recoverErr := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime, TrustStoreOptions{})
			if recoverErr != nil {
				t.Fatal(recoverErr)
			}
			if recovered.Active != published.Active {
				t.Fatalf("recovered active=%#v want=%#v", recovered.Active, published.Active)
			}
			assertTrustStoreLayout(t, root, 1)
		})
	}
}

func TestApplyAuthenticatedTrustBundleWithdrawalReplaysRotatedPublishHistory(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	currentPolicy, currentKeys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 4, 3)
	initial := newTrustStoreTestFixtureWithKeys(t, 7, currentPolicy, currentKeys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, initial.bundle, initial.envelope, currentPolicy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = 8
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, nextPolicy, nextKeys[:nextPolicy.Threshold], nil)
	publishDocument := trustUpdateOperationDocument(t, published.Active, currentPolicy, nextPolicy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	publishSigners := append(append([]trustMetadataTestKey(nil), currentKeys[:currentPolicy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	publishOperation := trustUpdateOperationEnvelope(t, publishDocument, publishSigners)
	updated, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, publishOperation, currentPolicy, nextPolicy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	withdrawalTime := trustUpdateEvaluationTime.Add(2 * time.Hour)
	withdrawDocument := trustUpdateOperationDocument(t, updated.Active, nextPolicy, nextPolicy, 9, trustUpdateActionWithdraw, nil, nil, withdrawalTime)
	withdrawOperation := trustUpdateOperationEnvelope(t, withdrawDocument, nextKeys[:nextPolicy.Threshold])
	withdrawal, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, withdrawOperation, nextPolicy, nextPolicy, withdrawalTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if withdrawal.PreviousGeneration != updated.Generation || withdrawal.AuthorizationPlan.CurrentKeySetVersion != nextPolicy.Version {
		t.Fatalf("rotated history was not preserved: %#v", withdrawal)
	}
	if _, err := RecoverAuthenticatedTrustBundleWithdrawal(context.Background(), root, nextPolicy, withdrawalTime.AddDate(1, 0, 0), TrustStoreOptions{}); err != nil {
		t.Fatal(err)
	}
	assertTrustStoreLayout(t, root, 3)
}

func TestRecoverAuthenticatedTrustBundleWithdrawalRejectsTamperedEvidence(t *testing.T) {
	root, policy, _, _, operation, _ := newTrustWithdrawalTestFixture(t)
	withdrawal, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	generationPath := filepath.Join(root, trustStoreGenerationsName, withdrawal.Generation)
	if err := os.Chmod(generationPath, 0o700); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(generationPath, trustStoreEvidenceName)
	if err := os.Chmod(evidencePath, 0o600); err != nil {
		t.Fatal(err)
	}
	var evidence TrustStoreGenerationEvidence
	if err := json.Unmarshal(readTrustUpdateTestFile(t, evidencePath), &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.OperationBase64 = "A" + evidence.OperationBase64[1:]
	evidenceData, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, evidenceData, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(evidenceData)
	active := withdrawal.Active
	active.EvidenceSHA256 = hex.EncodeToString(digest[:])
	activeData, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, trustStoreActiveName), activeData, 0o600); err != nil {
		t.Fatal(err)
	}
	sealTrustStoreGenerationForTest(t, generationPath)

	if _, err := RecoverAuthenticatedTrustBundleWithdrawal(context.Background(), root, policy, trustUpdateEvaluationTime, TrustStoreOptions{}); err == nil {
		t.Fatal("tampered withdrawal evidence was accepted")
	}
}

func TestWithdrawnEvidenceCannotBeRecastAsAnActiveBundle(t *testing.T) {
	root, policy, _, _, operation, _ := newTrustWithdrawalTestFixture(t)
	withdrawal, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	active := withdrawal.Active
	active.Purpose = trustStoreActivePurpose
	activeData, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, trustStoreActiveName), activeData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime, TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("recast tombstone error=%v", err)
	}
}

func TestApplyAuthenticatedTrustBundleWithdrawalRejectsPublishAndCancellation(t *testing.T) {
	root, policy, keys, published, _, _ := newTrustWithdrawalTestFixture(t)
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = published.Active.Sequence + 1
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], nil)
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, candidate.Sequence, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	before := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
	if _, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{}); err == nil {
		t.Fatal("publish operation was accepted by withdrawal executor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(ctx, root, operation, policy, policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{}); err == nil {
		t.Fatal("cancelled withdrawal was accepted")
	}
	after := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
	if string(after) != string(before) {
		t.Fatal("rejected withdrawal changed active state")
	}
	assertTrustStoreLayout(t, root, 1)
}

func FuzzParseTrustStoreWithdrawalEvidenceDoesNotPanic(f *testing.F) {
	f.Add([]byte(`{"schema":1,"purpose":"ffu-trust-bundle-withdrawal-generation"}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTrustStoreEvidence(data)
	})
}

func newTrustWithdrawalTestFixture(t *testing.T) (string, TrustMetadataPolicy, []trustMetadataTestKey, TrustStoreResult, []byte, string) {
	t.Helper()
	root := newTrustStoreTestRoot(t)
	policy, keys := trustMetadataTestPolicy(t, 3, 2)
	document := validTrustBundleDocument(t)
	distrust := strings.Repeat("ab", sha256.Size)
	document.DistrustedSHA256 = []string{distrust}
	bundle := marshalTrustBundle(t, document)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:policy.Threshold], nil)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, bundle, envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	operationDocument := trustUpdateOperationDocument(t, published.Active, policy, policy, published.Active.Sequence+1, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, operationDocument, keys[:policy.Threshold])
	return root, policy, keys, published, operation, distrust
}

func assertTrustWithdrawalResult(t *testing.T, withdrawal TrustBundleWithdrawal, published TrustStoreResult, distrust string) {
	t.Helper()
	if withdrawal.Generation == "" || withdrawal.PreviousGeneration != published.Generation || withdrawal.Active.Purpose != trustStoreWithdrawnPurpose || withdrawal.Active.Sequence != published.Active.Sequence+1 {
		t.Fatalf("incomplete withdrawal result: %#v", withdrawal)
	}
	if !withdrawal.WithdrawalPerformed || withdrawal.PublicationPerformed || withdrawal.TrustAnchorsActivated || withdrawal.HostTLSStoreConsulted || withdrawal.CertificateChainBuilt || withdrawal.PublisherTrusted {
		t.Fatalf("withdrawal crossed a later trust boundary: %#v", withdrawal)
	}
	if withdrawal.AuthorizationPlan.Action != trustUpdateActionWithdraw || !withdrawal.AuthorizationPlan.OperationAuthenticated || withdrawal.AuthorizationPlan.CandidateAuthenticated || withdrawal.AuthorizationPlan.PolicyRotated {
		t.Fatalf("invalid withdrawal authorization plan: %#v", withdrawal.AuthorizationPlan)
	}
	if len(withdrawal.PreservedDistrustedSHA256) != 1 || withdrawal.PreservedDistrustedSHA256[0] != distrust {
		t.Fatalf("preserved distrust=%v want=%s", withdrawal.PreservedDistrustedSHA256, distrust)
	}
}
