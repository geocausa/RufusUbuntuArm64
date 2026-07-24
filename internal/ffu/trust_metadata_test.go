package ffu

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

var trustMetadataEvaluationTime = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

type trustMetadataTestKey struct {
	document TrustMetadataKey
	private  ed25519.PrivateKey
}

func TestAuthenticateTrustBundleMetadataValidThresholdRemainsInactive(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 3, 2)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:2], nil)

	plan, err := AuthenticateTrustBundleMetadata(bundle, envelope, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.BundleStructureValidated || !plan.BundleSignatureAuthenticated {
		t.Fatalf("bundle was not authenticated: %#v", plan)
	}
	if plan.TrustAnchorsActivated || plan.CertificateChainBuilt || plan.PublisherTrusted || plan.HostTLSStoreConsulted {
		t.Fatalf("authentication crossed an inactive trust boundary: %#v", plan)
	}
	if plan.Authentication == nil {
		t.Fatal("authentication evidence is missing")
	}
	if plan.Authentication.Sequence != plan.Sequence || plan.Authentication.BundleSHA256 != plan.BundleSHA256 {
		t.Fatalf("metadata is not bound to the bundle: %#v", plan.Authentication)
	}
	if plan.Authentication.Threshold != 2 || len(plan.Authentication.SigningKeyIDs) != 2 {
		t.Fatalf("unexpected threshold evidence: %#v", plan.Authentication)
	}
	if !sort.StringsAreSorted(plan.Authentication.SigningKeyIDs) {
		t.Fatalf("signing keys are not deterministic: %#v", plan.Authentication.SigningKeyIDs)
	}
	if len(plan.Authentication.MetadataSHA256) != sha256.Size*2 || len(plan.PlanSHA256) != sha256.Size*2 {
		t.Fatalf("missing authentication digests: %#v", plan)
	}

	second, err := AuthenticateTrustBundleMetadata(bundle, envelope, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != plan.PlanSHA256 || second.Authentication.MetadataSHA256 != plan.Authentication.MetadataSHA256 {
		t.Fatalf("authenticated plan is not deterministic: %#v %#v", plan, second)
	}
}

func TestAuthenticateTrustBundleMetadataRejectsSignatureFailures(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 3, 2)

	unknownSeed := bytes.Repeat([]byte{0x7a}, ed25519.SeedSize)
	unknownPrivate := ed25519.NewKeyFromSeed(unknownSeed)
	unknownPublic := unknownPrivate.Public().(ed25519.PublicKey)
	unknownDigest := sha256.Sum256(unknownPublic)
	unknown := trustMetadataTestKey{
		document: TrustMetadataKey{
			ID:              hex.EncodeToString(unknownDigest[:]),
			Algorithm:       ffuTrustMetadataAlgorithm,
			PublicKeyBase64: base64.StdEncoding.EncodeToString(unknownPublic),
		},
		private: unknownPrivate,
	}

	tests := []struct {
		name  string
		build func() []byte
		want  string
	}{
		{
			name:  "insufficient threshold",
			build: func() []byte { return trustMetadataEnvelope(t, bundle, policy, keys[:1], nil) },
			want:  "threshold",
		},
		{
			name: "unknown key",
			build: func() []byte {
				return trustMetadataEnvelope(t, bundle, policy, []trustMetadataTestKey{keys[0], unknown}, nil)
			},
			want: "unknown key",
		},
		{
			name: "duplicate signature",
			build: func() []byte {
				envelope := decodeTrustMetadataEnvelope(t, trustMetadataEnvelope(t, bundle, policy, keys[:2], nil))
				envelope.Signatures = append(envelope.Signatures, envelope.Signatures[1])
				return marshalTrustMetadataEnvelope(t, envelope)
			},
			want: "repeats signature",
		},
		{
			name: "unknown algorithm",
			build: func() []byte {
				envelope := decodeTrustMetadataEnvelope(t, trustMetadataEnvelope(t, bundle, policy, keys[:2], nil))
				envelope.Signatures[0].Algorithm = "rsa-sha256"
				return marshalTrustMetadataEnvelope(t, envelope)
			},
			want: "unsupported algorithm",
		},
		{
			name: "wrong signature",
			build: func() []byte {
				envelope := decodeTrustMetadataEnvelope(t, trustMetadataEnvelope(t, bundle, policy, keys[:2], nil))
				signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Signature)
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				envelope.Signatures[0].Signature = base64.StdEncoding.EncodeToString(signature)
				return marshalTrustMetadataEnvelope(t, envelope)
			},
			want: "verify",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AuthenticateTrustBundleMetadata(bundle, test.build(), policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestAuthenticateTrustBundleMetadataRejectsPayloadAndPolicyMismatch(t *testing.T) {
	baseBundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	bundle := append([]byte{' '}, baseBundle...)
	policy, keys := trustMetadataTestPolicy(t, 3, 2)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys[:2], nil)

	altered := append([]byte(nil), bundle...)
	altered[0] = '\n'
	if _, err := AuthenticateTrustBundleMetadata(altered, envelope, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("altered bundle error=%v", err)
	}

	modifiedPolicy := policy
	modifiedPolicy.Version++
	if _, err := AuthenticateTrustBundleMetadata(bundle, envelope, modifiedPolicy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "key-set version") {
		t.Fatalf("policy version error=%v", err)
	}

	modifiedPolicy = policy
	modifiedPolicy.Threshold = 1
	if _, err := AuthenticateTrustBundleMetadata(bundle, envelope, modifiedPolicy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("policy threshold error=%v", err)
	}

	modifiedPolicy = policy
	modifiedPolicy.Keys = append([]TrustMetadataKey(nil), policy.Keys...)
	modifiedPolicy.Keys[0].PublicKeyBase64 = policy.Keys[1].PublicKeyBase64
	if _, err := AuthenticateTrustBundleMetadata(bundle, envelope, modifiedPolicy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "does not match its public key") {
		t.Fatalf("policy key error=%v", err)
	}
}

func TestAuthenticateTrustBundleMetadataRejectsCanonicalityExpiryAndSequence(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 3, 2)

	noncanonical := trustMetadataEnvelope(t, bundle, policy, keys[:2], func(document *TrustMetadataDocument) {})
	envelope := decodeTrustMetadataEnvelope(t, noncanonical)
	var indented bytes.Buffer
	if err := json.Indent(&indented, envelope.Signed, "", "  "); err != nil {
		t.Fatal(err)
	}
	signaturesJSON, err := json.Marshal(envelope.Signatures)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalEnvelope := append([]byte(`{"signed":`), indented.Bytes()...)
	noncanonicalEnvelope = append(noncanonicalEnvelope, []byte(`,"signatures":`)...)
	noncanonicalEnvelope = append(noncanonicalEnvelope, signaturesJSON...)
	noncanonicalEnvelope = append(noncanonicalEnvelope, '}')
	if _, err := AuthenticateTrustBundleMetadata(bundle, noncanonicalEnvelope, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "canonical JSON") {
		t.Fatalf("canonical error=%v", err)
	}

	expired := trustMetadataEnvelope(t, bundle, policy, keys[:2], func(document *TrustMetadataDocument) {
		document.GeneratedAt = "2026-07-01T00:00:00Z"
		document.ExpiresAt = "2026-07-24T12:00:00Z"
	})
	if _, err := AuthenticateTrustBundleMetadata(bundle, expired, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry error=%v", err)
	}

	rollback := TrustMetadataRollbackState{Sequence: 8, BundleSHA256: strings.Repeat("00", sha256.Size)}
	if _, err := AuthenticateTrustBundleMetadata(bundle, trustMetadataEnvelope(t, bundle, policy, keys[:2], nil), policy, rollback, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "below rollback state") {
		t.Fatalf("rollback error=%v", err)
	}

	otherDigest := sha256.Sum256([]byte("different bundle"))
	reuse := TrustMetadataRollbackState{Sequence: 7, BundleSHA256: hex.EncodeToString(otherDigest[:])}
	if _, err := AuthenticateTrustBundleMetadata(bundle, trustMetadataEnvelope(t, bundle, policy, keys[:2], nil), policy, reuse, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "reuses a different") {
		t.Fatalf("sequence reuse error=%v", err)
	}
}

func TestAuthenticateTrustBundleMetadataRejectsMissingDefaultsAndOversize(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 1, 1)
	envelope := trustMetadataEnvelope(t, bundle, policy, keys, nil)

	if _, err := AuthenticateTrustBundleMetadata(bundle, envelope, TrustMetadataPolicy{}, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "version must be non-zero") {
		t.Fatalf("empty production policy error=%v", err)
	}
	oversized := bytes.Repeat([]byte{' '}, maxFFUTrustMetadataBytes+1)
	if _, err := AuthenticateTrustBundleMetadata(bundle, oversized, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error=%v", err)
	}
	if _, err := AuthenticateTrustBundleMetadata(bundle, envelope, policy, TrustMetadataRollbackState{}, time.Time{}); err == nil || !strings.Contains(err.Error(), "evaluation time is zero") {
		t.Fatalf("zero time error=%v", err)
	}
}

func TestAuthenticateTrustBundleMetadataRejectsNoncanonicalBase64(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 2, 1)

	noncanonicalPolicy := policy
	noncanonicalPolicy.Keys = append([]TrustMetadataKey(nil), policy.Keys...)
	noncanonicalPolicy.Keys[0].PublicKeyBase64 = noncanonicalPolicy.Keys[0].PublicKeyBase64[:4] + "\n" + noncanonicalPolicy.Keys[0].PublicKeyBase64[4:]
	if _, err := CanonicalTrustMetadataPolicySHA256(noncanonicalPolicy); err == nil || !strings.Contains(err.Error(), "canonical padded base64") {
		t.Fatalf("noncanonical public-key base64 error=%v", err)
	}

	envelope := decodeTrustMetadataEnvelope(t, trustMetadataEnvelope(t, bundle, policy, keys[:1], nil))
	envelope.Signatures[0].Signature = envelope.Signatures[0].Signature[:8] + "\n" + envelope.Signatures[0].Signature[8:]
	if _, err := AuthenticateTrustBundleMetadata(bundle, marshalTrustMetadataEnvelope(t, envelope), policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), "canonical padded base64") {
		t.Fatalf("noncanonical signature base64 error=%v", err)
	}
}

func FuzzAuthenticateTrustBundleMetadataDoesNotPanic(f *testing.F) {
	bundle := marshalTrustBundleForFuzz(validTrustBundleDocumentForFuzz())
	policy, keys := trustMetadataTestPolicyWithoutTest(2, 1)
	envelope := trustMetadataEnvelopeWithoutTest(bundle, policy, keys[:1], nil)
	f.Add(bundle, envelope)
	f.Add([]byte("not a bundle"), []byte("not metadata"))
	f.Fuzz(func(t *testing.T, bundleData, envelopeData []byte) {
		_, _ = AuthenticateTrustBundleMetadata(bundleData, envelopeData, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime)
	})
}

func trustMetadataTestPolicy(t *testing.T, count, threshold int) (TrustMetadataPolicy, []trustMetadataTestKey) {
	t.Helper()
	return trustMetadataTestPolicyWithoutTest(count, threshold)
}

func trustMetadataTestPolicyWithoutTest(count, threshold int) (TrustMetadataPolicy, []trustMetadataTestKey) {
	keys := make([]trustMetadataTestKey, 0, count)
	for index := 0; index < count; index++ {
		seed := bytes.Repeat([]byte{byte(0x31 + index)}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		digest := sha256.Sum256(publicKey)
		keys = append(keys, trustMetadataTestKey{
			document: TrustMetadataKey{
				ID:              hex.EncodeToString(digest[:]),
				Algorithm:       ffuTrustMetadataAlgorithm,
				PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
			},
			private: privateKey,
		})
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].document.ID < keys[right].document.ID })
	documents := make([]TrustMetadataKey, len(keys))
	for index := range keys {
		documents[index] = keys[index].document
	}
	return TrustMetadataPolicy{Version: 3, Threshold: threshold, Keys: documents}, keys
}

func trustMetadataEnvelope(t *testing.T, bundle []byte, policy TrustMetadataPolicy, signers []trustMetadataTestKey, mutate func(*TrustMetadataDocument)) []byte {
	t.Helper()
	data, err := trustMetadataEnvelopeData(bundle, policy, signers, mutate)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func trustMetadataEnvelopeWithoutTest(bundle []byte, policy TrustMetadataPolicy, signers []trustMetadataTestKey, mutate func(*TrustMetadataDocument)) []byte {
	data, err := trustMetadataEnvelopeData(bundle, policy, signers, mutate)
	if err != nil {
		panic(err)
	}
	return data
}

func trustMetadataEnvelopeData(bundle []byte, policy TrustMetadataPolicy, signers []trustMetadataTestKey, mutate func(*TrustMetadataDocument)) ([]byte, error) {
	policyDigest, err := CanonicalTrustMetadataPolicySHA256(policy)
	if err != nil {
		return nil, err
	}
	bundleDigest := sha256.Sum256(bundle)
	var bundleDocument TrustBundleDocument
	if err := json.Unmarshal(bundle, &bundleDocument); err != nil {
		return nil, err
	}
	document := TrustMetadataDocument{
		Schema:        ffuTrustMetadataSchema,
		Purpose:       ffuTrustMetadataPurpose,
		Sequence:      bundleDocument.Sequence,
		KeySetVersion: policy.Version,
		KeySetSHA256:  policyDigest,
		Threshold:     policy.Threshold,
		GeneratedAt:   "2026-07-01T00:00:00Z",
		ExpiresAt:     "2027-06-30T00:00:00Z",
		BundleSize:    uint64(len(bundle)),
		BundleSHA256:  hex.EncodeToString(bundleDigest[:]),
	}
	if mutate != nil {
		mutate(&document)
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	signatures := make([]TrustMetadataSignature, 0, len(signers))
	for _, signer := range signers {
		signatures = append(signatures, TrustMetadataSignature{
			KeyID:     signer.document.ID,
			Algorithm: ffuTrustMetadataAlgorithm,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer.private, canonical)),
		})
	}
	sort.Slice(signatures, func(left, right int) bool { return signatures[left].KeyID < signatures[right].KeyID })
	return json.Marshal(TrustMetadataEnvelope{Signed: canonical, Signatures: signatures})
}

func decodeTrustMetadataEnvelope(t *testing.T, data []byte) TrustMetadataEnvelope {
	t.Helper()
	var envelope TrustMetadataEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func marshalTrustMetadataEnvelope(t *testing.T, envelope TrustMetadataEnvelope) []byte {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAuthenticateTrustBundleMetadataRejectsDuplicateJSONMembers(t *testing.T) {
	bundle := marshalTrustBundle(t, validTrustBundleDocument(t))
	policy, keys := trustMetadataTestPolicy(t, 2, 1)
	envelope := decodeTrustMetadataEnvelope(t, trustMetadataEnvelope(t, bundle, policy, keys[:1], nil))
	signaturesJSON, err := json.Marshal(envelope.Signatures)
	if err != nil {
		t.Fatal(err)
	}

	duplicateEnvelope := append([]byte(`{"signed":`), envelope.Signed...)
	duplicateEnvelope = append(duplicateEnvelope, []byte(`,"signed":`)...)
	duplicateEnvelope = append(duplicateEnvelope, envelope.Signed...)
	duplicateEnvelope = append(duplicateEnvelope, []byte(`,"signatures":`)...)
	duplicateEnvelope = append(duplicateEnvelope, signaturesJSON...)
	duplicateEnvelope = append(duplicateEnvelope, '}')
	if _, err := AuthenticateTrustBundleMetadata(bundle, duplicateEnvelope, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), `duplicate JSON object member "signed"`) {
		t.Fatalf("duplicate envelope error=%v", err)
	}

	canonical := string(envelope.Signed)
	duplicateSigned := strings.Replace(canonical, `"schema":1`, `"schema":1,"schema":1`, 1)
	duplicatePayload := append([]byte(`{"signed":`), []byte(duplicateSigned)...)
	duplicatePayload = append(duplicatePayload, []byte(`,"signatures":`)...)
	duplicatePayload = append(duplicatePayload, signaturesJSON...)
	duplicatePayload = append(duplicatePayload, '}')
	if _, err := AuthenticateTrustBundleMetadata(bundle, duplicatePayload, policy, TrustMetadataRollbackState{}, trustMetadataEvaluationTime); err == nil || !strings.Contains(err.Error(), `duplicate JSON object member "schema"`) {
		t.Fatalf("duplicate signed member error=%v", err)
	}
}

func TestTrustMetadataPolicyRequiresCanonicalDistinctKeys(t *testing.T) {
	policy, _ := trustMetadataTestPolicy(t, 2, 1)

	unsorted := policy
	unsorted.Keys = append([]TrustMetadataKey(nil), policy.Keys...)
	unsorted.Keys[0], unsorted.Keys[1] = unsorted.Keys[1], unsorted.Keys[0]
	if _, err := CanonicalTrustMetadataPolicySHA256(unsorted); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted policy error=%v", err)
	}

	duplicate := policy
	duplicate.Keys = []TrustMetadataKey{policy.Keys[0], policy.Keys[0]}
	if _, err := CanonicalTrustMetadataPolicySHA256(duplicate); err == nil || (!strings.Contains(err.Error(), "sorted") && !strings.Contains(err.Error(), "repeats")) {
		t.Fatalf("duplicate policy error=%v", err)
	}

	unknownAlgorithm := policy
	unknownAlgorithm.Keys = append([]TrustMetadataKey(nil), policy.Keys...)
	unknownAlgorithm.Keys[0].Algorithm = "rsa-sha256"
	if _, err := CanonicalTrustMetadataPolicySHA256(unknownAlgorithm); err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("algorithm policy error=%v", err)
	}
}
