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

func TestApplyAuthenticatedTrustBundlePublishOperationAndRecover(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := newTrustStoreTestFixtureWithKeys(t, 8, policy, keys)
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])

	result, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation, policy, policy, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveTrustUpdateExecution(t, result)
	if result.PreviousGeneration != published.Generation || result.Active.Sequence != 8 || result.AuthorizationPlan.PolicyRotated {
		t.Fatalf("unexpected signed publish result: %#v", result)
	}
	assertTrustStoreLayout(t, root, 2)

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Generation != result.Generation || recovered.Active != result.Active || recovered.Plan.Sequence != 8 {
		t.Fatalf("recovered wrong signed publish generation: %#v", recovered)
	}
	assertInactiveTrustStoreResult(t, recovered)

	evidence := readTrustUpdateGenerationEvidence(t, root, result.Generation)
	if evidence.Purpose != trustStoreUpdateGenerationPurpose || evidence.UpdatePlanSHA256 != result.AuthorizationPlan.PlanSHA256 {
		t.Fatalf("signed publish evidence is incomplete: %#v", evidence)
	}
	decodedOperation, _, _, _, _, err := decodeTrustStoreUpdateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedOperation, operation) {
		t.Fatal("durable signed operation bytes changed")
	}
}

func TestApplyAuthenticatedTrustBundlePublishOperationRotatesPolicyAndRecovers(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	currentPolicy, currentKeys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 4, 3)
	current := newTrustStoreTestFixtureWithKeys(t, 7, currentPolicy, currentKeys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, currentPolicy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := newTrustStoreTestFixtureWithKeys(t, 8, nextPolicy, nextKeys)
	document := trustUpdateOperationDocument(t, published.Active, currentPolicy, nextPolicy, 8, trustUpdateActionPublish, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime)
	signers := append(append([]trustMetadataTestKey(nil), currentKeys[:currentPolicy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	operation := trustUpdateOperationEnvelope(t, document, signers)

	result, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation, currentPolicy, nextPolicy, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveTrustUpdateExecution(t, result)
	if !result.AuthorizationPlan.PolicyRotated || !result.AuthorizationPlan.ReplacementPolicyAuthorized {
		t.Fatalf("rotation authorization was not preserved: %#v", result.AuthorizationPlan)
	}

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, nextPolicy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != result.Active || recovered.Plan.Authentication == nil || recovered.Plan.Authentication.KeySetVersion != nextPolicy.Version {
		t.Fatalf("rotated policy was not recovered: %#v", recovered)
	}
	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, currentPolicy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("old policy recovered rotated generation: %v", err)
	}
}

func TestApplyAuthenticatedTrustBundlePublishOperationReplaysUpdateHistory(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	currentPolicy, currentKeys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 4, 3)
	current := newTrustStoreTestFixtureWithKeys(t, 7, currentPolicy, currentKeys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, currentPolicy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}

	candidate8 := newTrustStoreTestFixtureWithKeys(t, 8, nextPolicy, nextKeys)
	document8 := trustUpdateOperationDocument(t, published.Active, currentPolicy, nextPolicy, 8, trustUpdateActionPublish, candidate8.bundle, candidate8.envelope, trustUpdateEvaluationTime)
	signers8 := append(append([]trustMetadataTestKey(nil), currentKeys[:currentPolicy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	operation8 := trustUpdateOperationEnvelope(t, document8, signers8)
	result8, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation8, currentPolicy, nextPolicy, candidate8.bundle, candidate8.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	evaluation9 := trustUpdateEvaluationTime.Add(time.Hour)
	candidate9 := newTrustStoreTestFixtureWithKeys(t, 9, nextPolicy, nextKeys)
	document9 := trustUpdateOperationDocument(t, result8.Active, nextPolicy, nextPolicy, 9, trustUpdateActionPublish, candidate9.bundle, candidate9.envelope, evaluation9)
	operation9 := trustUpdateOperationEnvelope(t, document9, nextKeys[:nextPolicy.Threshold])
	result9, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation9, nextPolicy, nextPolicy, candidate9.bundle, candidate9.envelope, evaluation9, TrustUpdateApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result9.PreviousGeneration != result8.Generation || result9.Active.Sequence != 9 {
		t.Fatalf("unexpected chained signed publish: %#v", result9)
	}

	recovered, err := RecoverAuthenticatedTrustBundle(context.Background(), root, nextPolicy, evaluation9.Add(time.Hour), TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Active != result9.Active || recovered.Plan.Sequence != 9 {
		t.Fatalf("signed update history was not replayed: %#v", recovered)
	}
	assertTrustStoreLayout(t, root, 3)
}

func TestApplyAuthenticatedTrustBundlePublishOperationRefusesWithdrawalWithoutMutation(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	document := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:fixture.policy.Threshold])

	_, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation, fixture.policy, fixture.policy, nil, nil, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "publish operations only") {
		t.Fatalf("withdrawal apply error=%v", err)
	}
	recovered, recoverErr := RecoverAuthenticatedTrustBundle(context.Background(), root, fixture.policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
	if recoverErr != nil {
		t.Fatal(recoverErr)
	}
	if recovered.Active != published.Active {
		t.Fatalf("withdrawal refusal changed active state: %#v", recovered)
	}
	assertTrustStoreLayout(t, root, 1)
}

func TestApplyAuthenticatedTrustBundlePublishOperationRollsBackEveryStage(t *testing.T) {
	stages := []string{"authorized", "generation-created", "bundle-staged", "metadata-staged", "evidence-staged", "generation-synced", "generation-published", "active-staged", "active-committed", "verified"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root := newTrustStoreTestRoot(t)
			policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
			current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
			published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
			if err != nil {
				t.Fatal(err)
			}
			candidate := newTrustStoreTestFixtureWithKeys(t, 8, policy, keys)
			document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime)
			operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
			_, err = ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation, policy, policy, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("stage %s error=%v", stage, err)
			}
			recovered, recoverErr := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{})
			if recoverErr != nil {
				t.Fatal(recoverErr)
			}
			if recovered.Active != published.Active || recovered.Generation != published.Generation {
				t.Fatalf("failed signed publish changed active state: %#v", recovered)
			}
			assertTrustStoreLayout(t, root, 1)
		})
	}
}

func TestRecoverAuthenticatedTrustBundleRejectsTamperedSignedUpdateEvidence(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := newTrustStoreTestFixtureWithKeys(t, 8, policy, keys)
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	result, err := ApplyAuthenticatedTrustBundlePublishOperation(context.Background(), root, operation, policy, policy, candidate.bundle, candidate.envelope, trustUpdateEvaluationTime, TrustUpdateApplyOptions{})
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

	if _, err := RecoverAuthenticatedTrustBundle(context.Background(), root, policy, trustUpdateEvaluationTime.Add(time.Hour), TrustStoreOptions{}); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("tampered signed update evidence error=%v", err)
	}
}

func assertInactiveTrustUpdateExecution(t *testing.T, result TrustBundleUpdateExecutionResult) {
	t.Helper()
	if result.Generation == "" || result.Active.Generation != result.Generation || !result.PublicationPerformed || result.WithdrawalPerformed || result.TrustAnchorsActivated {
		t.Fatalf("incomplete signed trust update result: %#v", result)
	}
	if result.AuthorizationPlan.PublicationPerformed || result.AuthorizationPlan.WithdrawalPerformed || result.AuthorizationPlan.TrustAnchorsActivated || result.AuthorizationPlan.CertificateChainBuilt || result.AuthorizationPlan.PublisherTrusted {
		t.Fatalf("authorization plan crossed a later trust boundary: %#v", result.AuthorizationPlan)
	}
	if result.PublishedPlan.TrustAnchorsActivated || result.PublishedPlan.HostTLSStoreConsulted || result.PublishedPlan.CertificateChainBuilt || result.PublishedPlan.PublisherTrusted {
		t.Fatalf("published plan crossed the inactive trust boundary: %#v", result.PublishedPlan)
	}
}

func readTrustUpdateGenerationEvidence(t *testing.T, root, generation string) TrustStoreGenerationEvidence {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, trustStoreGenerationsName, generation, trustStoreEvidenceName))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := parseTrustStoreEvidence(data)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}
