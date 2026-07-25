//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var trustUpdateEvaluationTime = trustMetadataEvaluationTime.Add(2 * time.Hour)

func TestPlanAuthenticatedTrustBundlePublishReportsExactDelta(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}

	currentDocument := validTrustBundleDocument(t)
	oldFingerprint := currentDocument.Roots[0].CertificateSHA256
	candidateDocument := currentDocument
	candidateDocument.Sequence = 8
	candidateDocument.Roots = []TrustAnchorDocument{
		trustRootDocument(t, "oem.root", 0x43, 43),
		trustRootDocument(t, "test.root", 0x42, 42),
	}
	candidateDocument.DistrustedSHA256 = []string{oldFingerprint}
	candidateBundle := marshalTrustBundle(t, candidateDocument)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], nil)
	operationDocument := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, operationDocument, keys[:policy.Threshold])

	beforeActive := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName))
	plan, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != trustUpdateActionPublish || plan.Sequence != 8 || plan.PolicyRotated || !plan.CurrentStateValidated || !plan.OperationAuthenticated || !plan.CandidateAuthenticated {
		t.Fatalf("unexpected update plan state: %#v", plan)
	}
	if plan.PublicationPerformed || plan.WithdrawalPerformed || plan.TrustAnchorsActivated || plan.HostTLSStoreConsulted || plan.CertificateChainBuilt || plan.PublisherTrusted {
		t.Fatalf("planning crossed a mutation or later trust boundary: %#v", plan)
	}
	if len(plan.AddedRoots) != 1 || plan.AddedRoots[0].ID != "oem.root" {
		t.Fatalf("added roots=%#v", plan.AddedRoots)
	}
	if len(plan.RemovedRoots) != 0 || len(plan.ReplacedRoots) != 1 || plan.ReplacedRoots[0].ID != "test.root" || plan.ReplacedRoots[0].Before.CertificateSHA256 != oldFingerprint {
		t.Fatalf("root delta removed=%#v replaced=%#v", plan.RemovedRoots, plan.ReplacedRoots)
	}
	if len(plan.AddedDistrustSHA256) != 1 || plan.AddedDistrustSHA256[0] != oldFingerprint || len(plan.EmergencyDistrustSHA256) != 1 || plan.EmergencyDistrustSHA256[0] != oldFingerprint {
		t.Fatalf("distrust delta added=%#v emergency=%#v", plan.AddedDistrustSHA256, plan.EmergencyDistrustSHA256)
	}
	if len(plan.PlanSHA256) != sha256.Size*2 || plan.CandidatePlanSHA256 == "" || plan.OperationPayloadSHA256 == "" || plan.OperationEnvelopeSHA256 == "" {
		t.Fatalf("missing deterministic evidence: %#v", plan)
	}
	if got := readTrustUpdateTestFile(t, filepath.Join(root, trustStoreActiveName)); !bytes.Equal(got, beforeActive) {
		t.Fatal("read-only update planning changed the active record")
	}
	assertTrustStoreLayout(t, root, 1)

	second, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("deterministic plan changed: %s != %s", second.PlanSHA256, plan.PlanSHA256)
	}
}

func TestPlanAuthenticatedTrustBundleWithdrawReportsAllRemovals(t *testing.T) {
	root, fixture, published := publishedTrustStoreTestFixture(t)
	document := trustUpdateOperationDocument(t, published.Active, fixture.policy, fixture.policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	_, keys := trustMetadataTestPolicy(t, 3, 2)
	operation := trustUpdateOperationEnvelope(t, document, keys[:fixture.policy.Threshold])

	plan, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, fixture.policy, fixture.policy, nil, nil, trustUpdateEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != trustUpdateActionWithdraw || plan.CandidateAuthenticated || len(plan.RemovedRoots) != published.Plan.RootCount || len(plan.AddedRoots) != 0 || plan.WithdrawalPerformed {
		t.Fatalf("unexpected withdrawal plan: %#v", plan)
	}
	assertTrustStoreLayout(t, root, 1)
}

func TestPlanAuthenticatedTrustBundleRotationRequiresBothThresholds(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	currentPolicy, currentKeys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 4, 3)
	current := newTrustStoreTestFixtureWithKeys(t, 7, currentPolicy, currentKeys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, currentPolicy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = 8
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, nextPolicy, nextKeys[:nextPolicy.Threshold], nil)
	document := trustUpdateOperationDocument(t, published.Active, currentPolicy, nextPolicy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)

	tests := []struct {
		name    string
		signers []trustMetadataTestKey
		want    string
	}{
		{name: "current only", signers: currentKeys[:currentPolicy.Threshold], want: "replacement threshold"},
		{name: "replacement only", signers: nextKeys[:nextPolicy.Threshold], want: "current threshold"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := trustUpdateOperationEnvelope(t, document, test.signers)
			_, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, currentPolicy, nextPolicy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want=%q", err, test.want)
			}
		})
	}

	all := append(append([]trustMetadataTestKey(nil), currentKeys[:currentPolicy.Threshold]...), nextKeys[:nextPolicy.Threshold]...)
	operation := trustUpdateOperationEnvelope(t, document, all)
	plan, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, currentPolicy, nextPolicy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.PolicyRotated || !plan.ReplacementPolicyAuthorized || len(plan.OperationSigningKeyIDs) != currentPolicy.Threshold || len(plan.ReplacementSigningKeyIDs) != nextPolicy.Threshold || plan.CandidateAuthentication.KeySetVersion != nextPolicy.Version {
		t.Fatalf("unexpected rotation evidence: %#v", plan)
	}
}

func TestPlanAuthenticatedTrustBundleAllowsReplacingExpiredCurrentState(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}

	evaluation := time.Date(2027, 7, 2, 0, 0, 0, 0, time.UTC)
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = 8
	candidate.GeneratedAt = "2027-07-01T00:00:00Z"
	candidate.ExpiresAt = "2028-07-01T00:00:00Z"
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], func(document *TrustMetadataDocument) {
		document.GeneratedAt = "2027-07-01T00:00:00Z"
		document.ExpiresAt = "2028-06-30T00:00:00Z"
	})
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, evaluation)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])

	plan, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, evaluation)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CurrentMetadataExpired || !plan.CandidateAuthenticated {
		t.Fatalf("expired current state was not reported correctly: %#v", plan)
	}
}

func TestPlanAuthenticatedTrustBundleRejectsBindingsAndPolicyErrors(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = 8
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], nil)
	valid := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)

	tests := []struct {
		name     string
		mutate   func(*TrustUpdateOperationDocument)
		bundle   []byte
		metadata []byte
		next     TrustMetadataPolicy
		want     string
	}{
		{name: "current generation", mutate: func(document *TrustUpdateOperationDocument) { document.CurrentGeneration += "x" }, bundle: candidateBundle, metadata: candidateMetadata, next: policy, want: "current-state binding"},
		{name: "candidate digest", mutate: func(document *TrustUpdateOperationDocument) { document.CandidateBundleSHA256 = strings.Repeat("0", 64) }, bundle: candidateBundle, metadata: candidateMetadata, next: policy, want: "candidate byte binding"},
		{name: "rollback sequence", mutate: func(document *TrustUpdateOperationDocument) { document.Sequence = 7 }, bundle: candidateBundle, metadata: candidateMetadata, next: policy, want: "must exceed"},
		{name: "unknown action", mutate: func(document *TrustUpdateOperationDocument) { document.Action = "delete" }, bundle: candidateBundle, metadata: candidateMetadata, next: policy, want: "unsupported"},
		{name: "withdraw carries candidate", mutate: func(document *TrustUpdateOperationDocument) { document.Action = trustUpdateActionWithdraw }, bundle: candidateBundle, metadata: candidateMetadata, next: policy, want: "must not carry"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := valid
			test.mutate(&document)
			operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
			_, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, test.next, test.bundle, test.metadata, trustUpdateEvaluationTime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want=%q", err, test.want)
			}
		})
	}

	changedPolicy, changedKeys := trustUpdateTestPolicy(0x71, 3, 3, 2)
	rotationDocument := trustUpdateOperationDocument(t, published.Active, policy, changedPolicy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, rotationDocument, append(keys[:policy.Threshold], changedKeys[:changedPolicy.Threshold]...))
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, changedPolicy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "advance exactly") {
		t.Fatalf("same-version rotation error=%v", err)
	}

	nextPolicy, nextKeys := trustUpdateTestPolicy(0x61, 4, 3, 2)
	withdrawDocument := trustUpdateOperationDocument(t, published.Active, policy, nextPolicy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation = trustUpdateOperationEnvelope(t, withdrawDocument, append(keys[:policy.Threshold], nextKeys[:nextPolicy.Threshold]...))
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, nextPolicy, nil, nil, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "rotation requires a publish") {
		t.Fatalf("withdrawal rotation error=%v", err)
	}
}

func TestPlanAuthenticatedTrustBundleRejectsEnvelopeAndSignatureAbuse(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	valid := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])

	var envelope TrustUpdateOperationEnvelope
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures[0].Signature = envelope.Signatures[0].Signature[:8] + "\n" + envelope.Signatures[0].Signature[8:]
	malformed, _ := json.Marshal(envelope)
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, malformed, policy, policy, nil, nil, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "canonical padded base64") {
		t.Fatalf("noncanonical signature error=%v", err)
	}

	unknownPolicy, unknownKeys := trustUpdateTestPolicy(0x71, 9, 1, 1)
	_ = unknownPolicy
	envelope = decodeTrustUpdateEnvelope(t, valid)
	canonical := append([]byte(nil), envelope.Signed...)
	envelope.Signatures = append(envelope.Signatures, trustUpdateSignature(unknownKeys[0], canonical))
	sort.Slice(envelope.Signatures, func(i, j int) bool { return envelope.Signatures[i].KeyID < envelope.Signatures[j].KeyID })
	unknown, _ := json.Marshal(envelope)
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, unknown, policy, policy, nil, nil, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unknown signature error=%v", err)
	}

	duplicate := strings.Replace(string(valid), `"schema":1`, `"schema":1,"schema":1`, 1)
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, []byte(duplicate), policy, policy, nil, nil, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "duplicate JSON") {
		t.Fatalf("duplicate member error=%v", err)
	}
}

func FuzzVerifyTrustUpdateOperationDoesNotPanic(f *testing.F) {
	policy, _ := trustMetadataTestPolicyWithoutTest(2, 1)
	verified, err := verifyTrustMetadataPolicy(policy)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("not json"))
	f.Add([]byte(`{"signed":{},"signatures":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = verifyTrustUpdateOperation(data, TrustStoreActiveRecord{}, TrustBundlePlan{}, trustMetadataEvaluationTime, verified, verified, nil, nil, trustUpdateEvaluationTime)
	})
}

func trustUpdateTestPolicy(seedStart byte, version uint64, count, threshold int) (TrustMetadataPolicy, []trustMetadataTestKey) {
	keys := make([]trustMetadataTestKey, 0, count)
	for index := 0; index < count; index++ {
		seed := bytes.Repeat([]byte{seedStart + byte(index)}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		digest := sha256.Sum256(publicKey)
		keys = append(keys, trustMetadataTestKey{
			document: TrustMetadataKey{ID: hex.EncodeToString(digest[:]), Algorithm: ffuTrustMetadataAlgorithm, PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey)},
			private:  privateKey,
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].document.ID < keys[j].document.ID })
	documents := make([]TrustMetadataKey, len(keys))
	for index := range keys {
		documents[index] = keys[index].document
	}
	return TrustMetadataPolicy{Version: version, Threshold: threshold, Keys: documents}, keys
}

func trustUpdateOperationDocument(t *testing.T, active TrustStoreActiveRecord, currentPolicy, nextPolicy TrustMetadataPolicy, sequence uint64, action string, candidateBundle, candidateMetadata []byte, evaluationTime time.Time) TrustUpdateOperationDocument {
	t.Helper()
	currentDigest, err := CanonicalTrustMetadataPolicySHA256(currentPolicy)
	if err != nil {
		t.Fatal(err)
	}
	nextDigest, err := CanonicalTrustMetadataPolicySHA256(nextPolicy)
	if err != nil {
		t.Fatal(err)
	}
	document := TrustUpdateOperationDocument{
		Schema:                       trustUpdateSchema,
		Purpose:                      trustUpdatePurpose,
		Sequence:                     sequence,
		Action:                       action,
		GeneratedAt:                  evaluationTime.Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                    evaluationTime.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		CurrentGeneration:            active.Generation,
		CurrentSequence:              active.Sequence,
		CurrentBundleSHA256:          active.BundleSHA256,
		CurrentEnvelopeSHA256:        active.EnvelopeSHA256,
		CurrentEvidenceSHA256:        active.EvidenceSHA256,
		CurrentPublicationPlanSHA256: active.PlanSHA256,
		CurrentKeySetVersion:         currentPolicy.Version,
		CurrentKeySetSHA256:          currentDigest,
		CurrentThreshold:             currentPolicy.Threshold,
		NextKeySetVersion:            nextPolicy.Version,
		NextKeySetSHA256:             nextDigest,
		NextThreshold:                nextPolicy.Threshold,
	}
	if action == trustUpdateActionPublish {
		bundleDigest := sha256.Sum256(candidateBundle)
		metadataDigest := sha256.Sum256(candidateMetadata)
		document.CandidateBundleSize = uint64(len(candidateBundle))
		document.CandidateBundleSHA256 = hex.EncodeToString(bundleDigest[:])
		document.CandidateMetadataSize = uint64(len(candidateMetadata))
		document.CandidateMetadataSHA256 = hex.EncodeToString(metadataDigest[:])
	}
	return document
}

func trustUpdateOperationEnvelope(t *testing.T, document TrustUpdateOperationDocument, signers []trustMetadataTestKey) []byte {
	t.Helper()
	canonical, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]TrustUpdateSignature, 0, len(signers))
	seen := make(map[string]struct{})
	for _, signer := range signers {
		if _, exists := seen[signer.document.ID]; exists {
			continue
		}
		seen[signer.document.ID] = struct{}{}
		signatures = append(signatures, trustUpdateSignature(signer, canonical))
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	data, err := json.Marshal(TrustUpdateOperationEnvelope{Signed: canonical, Signatures: signatures})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func trustUpdateSignature(signer trustMetadataTestKey, canonical []byte) TrustUpdateSignature {
	return TrustUpdateSignature{
		KeyID:     signer.document.ID,
		Algorithm: ffuTrustMetadataAlgorithm,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer.private, canonical)),
	}
}

func decodeTrustUpdateEnvelope(t *testing.T, data []byte) TrustUpdateOperationEnvelope {
	t.Helper()
	var envelope TrustUpdateOperationEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func readTrustUpdateTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPlanAuthenticatedTrustBundleRejectsTimeSequenceAndContextFailures(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := validTrustBundleDocument(t)
	candidate.Sequence = 8
	candidateBundle := marshalTrustBundle(t, candidate)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], nil)

	mismatched := trustUpdateOperationDocument(t, published.Active, policy, policy, 9, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, mismatched, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "does not match candidate") {
		t.Fatalf("candidate sequence mismatch error=%v", err)
	}

	expired := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	expired.GeneratedAt = trustUpdateEvaluationTime.Add(-48 * time.Hour).Format(time.RFC3339)
	expired.ExpiresAt = trustUpdateEvaluationTime.Add(-24 * time.Hour).Format(time.RFC3339)
	operation = trustUpdateOperationEnvelope(t, expired, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("expired operation error=%v", err)
	}

	//lint:ignore SA1012 This negative test intentionally verifies nil-context rejection.
	if _, err := PlanAuthenticatedTrustBundleOperation(nil, root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanAuthenticatedTrustBundleOperation(ctx, root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("cancelled context error=%v", err)
	}
}

func TestPlanAuthenticatedTrustBundleIsStrictlyReadOnlyForRecoveryTemporaries(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	activeTemp := trustStoreTempActive + strings.Repeat("a", 24)
	generationTemp := trustStoreTempGeneration + strings.Repeat("b", 24)
	if err := os.WriteFile(filepath.Join(root, activeTemp), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, trustStoreGenerationsName, generationTemp), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(root, activeTemp))
		_ = os.Remove(filepath.Join(root, trustStoreGenerationsName, generationTemp))
	})

	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, nil, nil, trustUpdateEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, activeTemp)); err != nil {
		t.Fatalf("planner removed temporary active record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, trustStoreGenerationsName, generationTemp)); err != nil {
		t.Fatalf("planner removed temporary generation: %v", err)
	}
}

func TestPlanAuthenticatedTrustBundleRejectsMissingStoreAndWrongCurrentPolicy(t *testing.T) {
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	next := policy
	document := TrustUpdateOperationDocument{}
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), t.TempDir(), operation, policy, next, nil, nil, trustUpdateEvaluationTime); err == nil {
		t.Fatal("missing trust store was accepted")
	}

	root := newTrustStoreTestRoot(t)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wrongPolicy, wrongKeys := trustUpdateTestPolicy(0x71, 3, 3, 2)
	document = trustUpdateOperationDocument(t, published.Active, wrongPolicy, wrongPolicy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation = trustUpdateOperationEnvelope(t, document, wrongKeys[:wrongPolicy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, wrongPolicy, wrongPolicy, nil, nil, trustUpdateEvaluationTime); err == nil {
		t.Fatal("wrong current policy was accepted")
	}
}

func TestPlanAuthenticatedTrustBundleRejectsCandidateTimeRegression(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	current := newTrustStoreTestFixtureWithKeys(t, 7, policy, keys)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, current.bundle, current.envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}

	bundleRegressed := validTrustBundleDocument(t)
	bundleRegressed.Sequence = 8
	bundleRegressed.GeneratedAt = "2026-06-30T00:00:00Z"
	candidateBundle := marshalTrustBundle(t, bundleRegressed)
	candidateMetadata := trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], nil)
	document := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "bundle generation time precedes") {
		t.Fatalf("bundle time regression error=%v", err)
	}

	metadataRegressed := validTrustBundleDocument(t)
	metadataRegressed.Sequence = 8
	candidateBundle = marshalTrustBundle(t, metadataRegressed)
	candidateMetadata = trustMetadataEnvelope(t, candidateBundle, policy, keys[:policy.Threshold], func(metadata *TrustMetadataDocument) {
		metadata.GeneratedAt = "2026-06-30T00:00:00Z"
	})
	document = trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionPublish, candidateBundle, candidateMetadata, trustUpdateEvaluationTime)
	operation = trustUpdateOperationEnvelope(t, document, keys[:policy.Threshold])
	if _, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, candidateBundle, candidateMetadata, trustUpdateEvaluationTime); err == nil || !strings.Contains(err.Error(), "metadata generation time precedes") {
		t.Fatalf("metadata time regression error=%v", err)
	}
}

func TestPlanAuthenticatedTrustBundleWithdrawalPreservesDistrustPolicy(t *testing.T) {
	root := newTrustStoreTestRoot(t)
	policy, keys := trustUpdateTestPolicy(0x31, 3, 3, 2)
	document := validTrustBundleDocument(t)
	document.Sequence = 7
	document.DistrustedSHA256 = []string{strings.Repeat("ab", sha256.Size)}
	bundle := marshalTrustBundle(t, document)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:policy.Threshold], nil)
	published, err := PublishAuthenticatedTrustBundle(context.Background(), root, bundle, envelope, policy, trustMetadataEvaluationTime, TrustStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	operationDocument := trustUpdateOperationDocument(t, published.Active, policy, policy, 8, trustUpdateActionWithdraw, nil, nil, trustUpdateEvaluationTime)
	operation := trustUpdateOperationEnvelope(t, operationDocument, keys[:policy.Threshold])
	plan, err := PlanAuthenticatedTrustBundleOperation(context.Background(), root, operation, policy, policy, nil, nil, trustUpdateEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RemovedDistrustSHA256) != 0 || len(plan.AddedDistrustSHA256) != 0 {
		t.Fatalf("withdrawal changed distrust policy: added=%#v removed=%#v", plan.AddedDistrustSHA256, plan.RemovedDistrustSHA256)
	}
}
