//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyAuthenticatedTrustBundleWithdrawalOperationAndRecover(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	document := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:fixture.policy.Threshold])

	result, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, fixture.policy, fixture.policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertWithdrawnTrustUpdateExecution(t, result)
	if result.PreviousGeneration != published.Generation || result.Active.Sequence != 8 || result.PublishedPlan.Sequence != published.Plan.Sequence {
		t.Fatalf("unexpected signed withdrawal result: %#v", result)
	}
	assertTrustStoreLayout(t, root, 2)

	previousBundle, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, published.Generation, trustStoreBundleName))
	if err != nil {
		t.Fatal(err)
	}
	tombstoneBundle, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, result.Generation, trustStoreBundleName))
	if err != nil {
		t.Fatal(err)
	}
	previousMetadata, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, published.Generation, trustStoreEnvelopeName))
	if err != nil {
		t.Fatal(err)
	}
	tombstoneMetadata, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, result.Generation, trustStoreEnvelopeName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previousBundle, tombstoneBundle) || !bytes.Equal(previousMetadata, tombstoneMetadata) {
		t.Fatal("withdrawal tombstone did not preserve the exact historical bundle and metadata bytes")
	}

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != result.Active || !recovered.Active.Withdrawn || recovered.Plan.PlanSHA256 != published.Plan.PlanSHA256 {
		t.Fatalf("recovered wrong signed withdrawal tombstone: %#v", recovered)
	}

	if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustActivationOptions{}); err == nil || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("withdrawn bundle activation error=%v", err)
	}

	nextDocument := trustUpdateOperationDocument(t, result.Active, fixture.policy, fixture.policy, 9, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime.Add(time.Hour))
	nextOperation := trustUpdateOperationEnvelope(t, nextDocument, keys[:fixture.policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, nextOperation, fixture.policy, fixture.policy, nil, nil, trustUpdateEvaluationTime.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("withdrawn trust store planned a second withdrawal: %v", err)
	}
	if _, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, nextOperation, fixture.policy, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustUpdateApplyOptions{}); err == nil || !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("withdrawn trust store accepted a second withdrawal: %v", err)
	}

	nextFixture := newTrustStoreTestFixtureWithPolicy(t, 9, fixture.policy)
	if _, err := PublishAuthenticatedTrustBundle(context.Background(), root, nextFixture.bundle, nextFixture.envelope, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "is withdrawn") {
		t.Fatalf("withdrawn trust store accepted direct publication: %v", err)
	}
	recoveredAfterRefusal, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recoveredAfterRefusal.Active != result.Active {
		t.Fatalf("rejected direct publication changed withdrawal tombstone: %#v", recoveredAfterRefusal)
	}

	evidence := readTrustUpdateGenerationEvidence(t, root, result.Generation)
	if evidence.Purpose != trustStoreWithdrawalGenerationPurpose || !evidence.Withdrawn || evidence.UpdatePlanSHA256 != result.AuthorizationPlan.PlanSHA256 {
		t.Fatalf("signed withdrawal evidence is incomplete: %#v", evidence)
	}
	decodedOperation, _, _, _, _, err := decodeTrustStoreUpdateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedOperation, operation) {
		t.Fatal("durable signed withdrawal operation bytes changed")
	}
}

func TestApplyAuthenticatedTrustBundleWithdrawalOperationReplaysPublishHistory(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	currentPolicy, currentKeys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 4, 3)
	current := newTrustStoreTestFixtureWithKeys(t, 7, currentPolicy, currentKeys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, currentPolicy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}

	candidate := newTrustStoreTestFixtureWithKeys(t, 8, nextPolicy, nextKeys)
	publishDocument := trustUpdateOperationDocument(t, published.Active, currentPolicy, nextPolicy, 8, trustUpdateActionPublish, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime)
	publishSigners := append(append([]trustMetadataTestKey(nil), currentKeys[:currentPolicy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	publishOperation := trustUpdateOperationEnvelope(t, publishDocument, publishSigners)
	publishResult, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, publishOperation, currentPolicy, nextPolicy, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	withdrawTime := trustUpdateEvaluationTime.Add(time.Hour)
	withdrawDocument := trustUpdateOperationDocument(t, publishResult.Active, nextPolicy, nextPolicy, 9, trustUpdateActionWithdraw, nil, nil, withdrawTime)
	withdrawOperation := trustUpdateOperationEnvelope(t, withdrawDocument, nextKeys[:nextPolicy.Threshold])
	withdrawResult, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, withdrawOperation, nextPolicy, nextPolicy, withdrawTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertWithdrawnTrustUpdateExecution(t, withdrawResult)
	if withdrawResult.PreviousGeneration != publishResult.Generation || withdrawResult.PublishedPlan.Sequence != 8 {
		t.Fatalf("withdrawal did not preserve published history: %#v", withdrawResult)
	}

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, nextPolicy, withdrawTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != withdrawResult.Active || recovered.Plan.Sequence != 8 || !recovered.Active.Withdrawn {
		t.Fatalf("signed publish/withdraw history was not replayed: %#v", recovered)
	}
	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, currentPolicy, withdrawTime.Add(time.Hour), TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("old policy recovered rotated withdrawal history: %v", err)
	}
	assertTrustStoreLayout(t, root, 3)
}

func TestSignedPublishSupersedesWithdrawalTombstone(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	withdrawDocument := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	withdrawOperation := trustUpdateOperationEnvelope(t, withdrawDocument, keys[:fixture.policy.Threshold])
	withdrawn, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, withdrawOperation, fixture.policy, fixture.policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	publishTime := trustUpdateEvaluationTime.Add(time.Hour)
	candidate := newTrustStoreTestFixtureWithPolicy(t, 9, fixture.policy)
	publishDocument := trustUpdateOperationDocument(t, withdrawn.Active, fixture.policy, fixture.policy, 9, trustUpdateActionPublish, candidate.bundle, candidate.envelope, publishTime)
	publishOperation := trustUpdateOperationEnvelope(t, publishDocument, keys[:fixture.policy.Threshold])
	publishedAgain, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, publishOperation, fixture.policy, fixture.policy, candidate.bundle, candidate.envelope, publishTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if publishedAgain.Active.Withdrawn || !publishedAgain.PublicationPerformed || publishedAgain.WithdrawalPerformed || publishedAgain.PreviousGeneration != withdrawn.Generation {
		t.Fatalf("signed publish did not supersede withdrawal tombstone: %#v", publishedAgain)
	}

	evidence := readTrustUpdateGenerationEvidence(t, root, publishedAgain.Generation)
	if !evidence.PreviousWithdrawn {
		t.Fatalf("signed publish did not preserve withdrawn predecessor evidence: %#v", evidence)
	}
	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, publishTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != publishedAgain.Active || recovered.Active.Withdrawn || recovered.Plan.Sequence != 9 {
		t.Fatalf("recovery did not replay withdrawal followed by signed publish: %#v", recovered)
	}
	if _, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, publishTime.Add(time.Hour), TrustActivationOptions{}); err != nil {
		t.Fatalf("superseding signed publish did not restore activation eligibility: %v", err)
	}
	assertTrustStoreLayout(t, root, 3)
}

func TestApplyAuthenticatedTrustBundleWithdrawalOperationRollsBackEveryStage(t *testing.T) {
	stages := []string{"authorized", "generation-created", "bundle-staged", "metadata-staged", "evidence-staged", "generation-synced", "generation-published", "active-staged", "active-committed", "verified"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root, fixture, published := publishedTrustStoreTestFixture(t)
			_, keys := trustMetadataTestPolicy(t, 3, 2)
			document := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
			operation := trustUpdateOperationEnvelope(t, document, keys[:fixture.policy.Threshold])
			_, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, fixture.policy, fixture.policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("stage %s error=%v", stage, err)
			}
			recovered, recoverErr := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
			if recoverErr != nil {
				t.Fatal(recoverErr)
			}
			if recovered.Active != published.Active || recovered.Generation != published.Generation || recovered.Active.Withdrawn {
				t.Fatalf("failed signed withdrawal changed active state: %#v", recovered)
			}
			assertTrustStoreLayout(t, root, 1)
		})
	}
}

func TestRecoverAuthenticatedTrustBundleRejectsTamperedWithdrawalSignature(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	document := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:fixture.policy.Threshold])
	result, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, fixture.policy, fixture.policy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	generationPath := filepath.Join(root, trustStoreGenerationsName, result.Generation)
	makeTrustStoreTreeWritableForTest(t, generationPath)
	evidencePath := filepath.Join(generationPath, trustStoreEvidenceName)
	evidence := readTrustUpdateGenerationEvidence(t, root, result.Generation)
	operationBytes, err := base64.StdEncoding.DecodeString(evidence.OperationBase64)
	if err != nil {
		t.Fatal(err)
	}
	var envelope TrustUpdateOperationEnvelope
	if err := json.Unmarshal(operationBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	envelope.Signatures[0].Signature = base64.StdEncoding.EncodeToString(signature)
	operationBytes, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	operationDigest := sha256.Sum256(operationBytes)
	evidence.OperationSize = uint64(len(operationBytes))
	evidence.OperationSHA256 = hex.EncodeToString(operationDigest[:])
	evidence.OperationBase64 = base64.StdEncoding.EncodeToString(operationBytes)
	evidenceData, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, evidenceData, 0o600); err != nil {
		t.Fatal(err)
	}
	sealTrustStoreGenerationForTest(t, generationPath)

	activePath := filepath.Join(root, trustStoreActiveName)
	activeData, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	var active TrustStoreActiveRecord
	if err := json.Unmarshal(activeData, &active); err != nil {
		t.Fatal(err)
	}
	evidenceDigest := sha256.Sum256(evidenceData)
	active.EvidenceSHA256 = hex.EncodeToString(evidenceDigest[:])
	activeData, err = json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, activeData, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("tampered signed withdrawal evidence error=%v", err)
	}
}

func TestApplyAuthenticatedTrustBundleWithdrawalOperationRejectsPolicyRotation(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	_, currentKeys := trustMetadataTestPolicy(t, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x71, fixture.policy.Version+1, 3, 2)
	document := trustUpdateOperationDocument(t, published.Active, fixture.policy, nextPolicy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	signers := append(append([]trustMetadataTestKey(nil), currentKeys[:fixture.policy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	operation := trustUpdateOperationEnvelope(t, document, signers)

	if _, err := ApplyAuthenticatedTrustBundleWithdrawalOperation(context.Background(), root, operation, fixture.policy, nextPolicy, trustUpdateEvaluationTime, TrustUpdateApplyOptions{}); err == nil || !strings.Contains(err.Error(), "rotation requires a publish") {
		t.Fatalf("withdrawal policy rotation error=%v", err)
	}
	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != published.Active {
		t.Fatalf("rejected withdrawal policy rotation changed active state: %#v", recovered)
	}
}

func assertWithdrawnTrustUpdateExecution(t *testing.T, result TrustBundleUpdateExecutionResult) {
	t.Helper()
	if result.Generation == "" || result.Active.Generation != result.Generation || !result.Active.Withdrawn || result.PublicationPerformed || !result.WithdrawalPerformed || result.TrustAnchorsActivated {
		t.Fatalf("incomplete signed trust withdrawal result: %#v", result)
	}
	if result.AuthorizationPlan.PublicationPerformed || result.AuthorizationPlan.WithdrawalPerformed || result.AuthorizationPlan.TrustAnchorsActivated || result.AuthorizationPlan.CertificateChainBuilt || result.AuthorizationPlan.PublisherTrusted {
		t.Fatalf("withdrawal authorization plan crossed a later trust boundary: %#v", result.AuthorizationPlan)
	}
	if result.PublishedPlan.TrustAnchorsActivated || result.PublishedPlan.HostTLSStoreConsulted || result.PublishedPlan.CertificateChainBuilt || result.PublishedPlan.PublisherTrusted {
		t.Fatalf("withdrawn historical plan crossed a later trust boundary: %#v", result.PublishedPlan)
	}
}
