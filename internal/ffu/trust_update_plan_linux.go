//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

const (
	trustUpdateSchema         = 1
	trustUpdatePurpose        = "ffu-trust-bundle-operation"
	trustUpdateActionPublish  = "publish"
	trustUpdateActionWithdraw = "withdraw"
	maxTrustUpdateBytes       = 256 << 10
	maxTrustUpdateSignatures  = 64
)

// TrustUpdateOperationDocument is the exact canonical payload approved by
// offline update operators. It binds the current durable generation, both
// authorization policies, and (for publish) the exact candidate bytes.
type TrustUpdateOperationDocument struct {
	Schema                       int    `json:"schema"`
	Purpose                      string `json:"purpose"`
	Sequence                     uint64 `json:"sequence"`
	Action                       string `json:"action"`
	GeneratedAt                  string `json:"generated_at"`
	ExpiresAt                    string `json:"expires_at"`
	CurrentGeneration            string `json:"current_generation"`
	CurrentSequence              uint64 `json:"current_sequence"`
	CurrentBundleSHA256          string `json:"current_bundle_sha256"`
	CurrentEnvelopeSHA256        string `json:"current_envelope_sha256"`
	CurrentEvidenceSHA256        string `json:"current_evidence_sha256"`
	CurrentPublicationPlanSHA256 string `json:"current_publication_plan_sha256"`
	CurrentKeySetVersion         uint64 `json:"current_key_set_version"`
	CurrentKeySetSHA256          string `json:"current_key_set_sha256"`
	CurrentThreshold             int    `json:"current_threshold"`
	NextKeySetVersion            uint64 `json:"next_key_set_version"`
	NextKeySetSHA256             string `json:"next_key_set_sha256"`
	NextThreshold                int    `json:"next_threshold"`
	CandidateBundleSize          uint64 `json:"candidate_bundle_size"`
	CandidateBundleSHA256        string `json:"candidate_bundle_sha256"`
	CandidateMetadataSize        uint64 `json:"candidate_metadata_size"`
	CandidateMetadataSHA256      string `json:"candidate_metadata_sha256"`
}

// TrustUpdateSignature uses the same self-authenticating Ed25519 key IDs as the
// bundle metadata policy, but signs the update-operation payload instead.
type TrustUpdateSignature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// TrustUpdateOperationEnvelope separates canonical signed bytes from the
// signatures that satisfy the current and, for rotation, replacement policy.
type TrustUpdateOperationEnvelope struct {
	Signed     json.RawMessage        `json:"signed"`
	Signatures []TrustUpdateSignature `json:"signatures"`
}

// TrustRootReplacement reports a stable root ID whose exact certificate
// fingerprint changes in the candidate bundle.
type TrustRootReplacement struct {
	ID     string      `json:"id"`
	Before TrustAnchor `json:"before"`
	After  TrustAnchor `json:"after"`
}

// TrustBundleUpdatePlan is a deterministic, read-only authorization and delta
// report. It cannot publish, withdraw, activate, build a chain, trust a
// publisher, access a target, or perform network I/O.
type TrustBundleUpdatePlan struct {
	Schema                       int                        `json:"schema"`
	Purpose                      string                     `json:"purpose"`
	Action                       string                     `json:"action"`
	Sequence                     uint64                     `json:"sequence"`
	GeneratedAt                  string                     `json:"generated_at"`
	ExpiresAt                    string                     `json:"expires_at"`
	EvaluationTime               string                     `json:"evaluation_time"`
	CurrentGeneration            string                     `json:"current_generation"`
	CurrentSequence              uint64                     `json:"current_sequence"`
	CurrentBundleSHA256          string                     `json:"current_bundle_sha256"`
	CurrentEnvelopeSHA256        string                     `json:"current_envelope_sha256"`
	CurrentEvidenceSHA256        string                     `json:"current_evidence_sha256"`
	CurrentPublicationPlanSHA256 string                     `json:"current_publication_plan_sha256"`
	CurrentReproducedPlanSHA256  string                     `json:"current_reproduced_plan_sha256"`
	CurrentPublicationTime       string                     `json:"current_publication_time"`
	CurrentBundleExpiresAt       string                     `json:"current_bundle_expires_at"`
	CurrentMetadataExpiresAt     string                     `json:"current_metadata_expires_at"`
	CurrentBundleExpired         bool                       `json:"current_bundle_expired"`
	CurrentMetadataExpired       bool                       `json:"current_metadata_expired"`
	CurrentKeySetVersion         uint64                     `json:"current_key_set_version"`
	CurrentKeySetSHA256          string                     `json:"current_key_set_sha256"`
	CurrentThreshold             int                        `json:"current_threshold"`
	CurrentSigningKeyIDs         []string                   `json:"current_signing_key_ids"`
	NextKeySetVersion            uint64                     `json:"next_key_set_version"`
	NextKeySetSHA256             string                     `json:"next_key_set_sha256"`
	NextThreshold                int                        `json:"next_threshold"`
	PolicyRotated                bool                       `json:"policy_rotated"`
	OperationSigningKeyIDs       []string                   `json:"operation_signing_key_ids"`
	ReplacementSigningKeyIDs     []string                   `json:"replacement_signing_key_ids,omitempty"`
	OperationPayloadSHA256       string                     `json:"operation_payload_sha256"`
	OperationEnvelopeSHA256      string                     `json:"operation_envelope_sha256"`
	CandidateBundleSize          uint64                     `json:"candidate_bundle_size,omitempty"`
	CandidateBundleSHA256        string                     `json:"candidate_bundle_sha256,omitempty"`
	CandidateMetadataSize        uint64                     `json:"candidate_metadata_size,omitempty"`
	CandidateMetadataSHA256      string                     `json:"candidate_metadata_sha256,omitempty"`
	CandidatePlanSHA256          string                     `json:"candidate_plan_sha256,omitempty"`
	CandidateBundleExpiresAt     string                     `json:"candidate_bundle_expires_at,omitempty"`
	CandidateMetadataExpiresAt   string                     `json:"candidate_metadata_expires_at,omitempty"`
	CandidateSigningKeyIDs       []string                   `json:"candidate_signing_key_ids,omitempty"`
	AddedRoots                   []TrustAnchor              `json:"added_roots"`
	RemovedRoots                 []TrustAnchor              `json:"removed_roots"`
	ReplacedRoots                []TrustRootReplacement     `json:"replaced_roots"`
	AddedDistrustSHA256          []string                   `json:"added_distrust_sha256"`
	RemovedDistrustSHA256        []string                   `json:"removed_distrust_sha256"`
	EmergencyDistrustSHA256      []string                   `json:"emergency_distrust_sha256"`
	CurrentStateValidated        bool                       `json:"current_state_validated"`
	OperationAuthenticated       bool                       `json:"operation_authenticated"`
	ReplacementPolicyAuthorized  bool                       `json:"replacement_policy_authorized"`
	CandidateAuthenticated       bool                       `json:"candidate_authenticated"`
	PublicationPerformed         bool                       `json:"publication_performed"`
	WithdrawalPerformed          bool                       `json:"withdrawal_performed"`
	TrustAnchorsActivated        bool                       `json:"trust_anchors_activated"`
	HostTLSStoreConsulted        bool                       `json:"host_tls_store_consulted"`
	CertificateChainBuilt        bool                       `json:"certificate_chain_built"`
	PublisherTrusted             bool                       `json:"publisher_trusted"`
	CurrentAuthentication        *TrustBundleAuthentication `json:"current_authentication"`
	CandidateAuthentication      *TrustBundleAuthentication `json:"candidate_authentication,omitempty"`
	PlanSHA256                   string                     `json:"plan_sha256"`
	Limitations                  []string                   `json:"limitations"`
}

type verifiedTrustUpdateOperation struct {
	document       TrustUpdateOperationDocument
	canonical      []byte
	currentKeyIDs  []string
	replacementIDs []string
	rotated        bool
}

// PlanAuthenticatedTrustBundleOperation authenticates and describes one
// offline publish or withdrawal operation. Current durable state is reproduced
// at its authenticated publication time so an expired active bundle can still
// be safely replaced or withdrawn. The operation and candidate are evaluated at
// evaluationTime. No durable state or trust authority is changed.
func PlanAuthenticatedTrustBundleOperation(
	ctx context.Context,
	root string,
	operationData []byte,
	currentPolicy TrustMetadataPolicy,
	nextPolicy TrustMetadataPolicy,
	candidateBundle []byte,
	candidateMetadata []byte,
	evaluationTime time.Time,
) (TrustBundleUpdatePlan, error) {
	if ctx == nil {
		return TrustBundleUpdatePlan{}, errors.New("FFU trust update context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if evaluationTime.IsZero() {
		return TrustBundleUpdatePlan{}, errors.New("FFU trust update evaluation time is zero")
	}
	if len(operationData) == 0 {
		return TrustBundleUpdatePlan{}, errors.New("FFU trust update operation is empty")
	}
	if len(operationData) > maxTrustUpdateBytes {
		return TrustBundleUpdatePlan{}, fmt.Errorf("FFU trust update operation exceeds %d-byte limit", maxTrustUpdateBytes)
	}

	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return TrustBundleUpdatePlan{}, fmt.Errorf("current FFU trust update policy: %w", err)
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return TrustBundleUpdatePlan{}, fmt.Errorf("replacement FFU trust update policy: %w", err)
	}

	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	defer rootFile.Close()
	generations, err := openTrustStoreDirectory(rootFile, trustStoreGenerationsName)
	if err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleUpdatePlan{}, err
	}

	active, currentPlan, publicationTime, err := loadTrustUpdateCurrentState(ctx, rootFile, generations, currentPolicy)
	if err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if !active.exists {
		return TrustBundleUpdatePlan{}, os.ErrNotExist
	}
	if err := requireInactiveAuthenticatedTrustPlan(currentPlan); err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if currentPlan.Authentication == nil || currentPlan.Authentication.KeySetVersion != currentVerified.version || currentPlan.Authentication.KeySetSHA256 != currentVerified.sha256 || currentPlan.Authentication.Threshold != currentVerified.threshold {
		return TrustBundleUpdatePlan{}, errors.New("current FFU trust update policy does not match durable authentication evidence")
	}
	verifiedOperation, err := verifyTrustUpdateOperation(operationData, active.record, currentPlan, publicationTime, currentVerified, nextVerified, candidateBundle, candidateMetadata, evaluationTime)
	if err != nil {
		return TrustBundleUpdatePlan{}, err
	}

	var candidatePlan *TrustBundlePlan
	if verifiedOperation.document.Action == trustUpdateActionPublish {
		plan, err := AuthenticateTrustBundleMetadata(
			candidateBundle,
			candidateMetadata,
			nextPolicy,
			TrustMetadataRollbackState{Sequence: active.record.Sequence, BundleSHA256: active.record.BundleSHA256},
			evaluationTime,
		)
		if err != nil {
			return TrustBundleUpdatePlan{}, fmt.Errorf("authenticate FFU trust update candidate: %w", err)
		}
		if err := requireInactiveAuthenticatedTrustPlan(plan); err != nil {
			return TrustBundleUpdatePlan{}, err
		}
		if plan.Sequence != verifiedOperation.document.Sequence {
			return TrustBundleUpdatePlan{}, errors.New("FFU trust update operation sequence does not match candidate bundle sequence")
		}
		currentGenerated, err := parseCanonicalTrustMetadataTime(currentPlan.GeneratedAt, "current.generated_at")
		if err != nil {
			return TrustBundleUpdatePlan{}, err
		}
		candidateGenerated, err := parseCanonicalTrustMetadataTime(plan.GeneratedAt, "candidate.generated_at")
		if err != nil {
			return TrustBundleUpdatePlan{}, err
		}
		if candidateGenerated.Before(currentGenerated) {
			return TrustBundleUpdatePlan{}, errors.New("FFU trust update candidate bundle generation time precedes current bundle")
		}
		currentMetadataGenerated, err := parseCanonicalTrustMetadataTime(currentPlan.Authentication.GeneratedAt, "current.authentication.generated_at")
		if err != nil {
			return TrustBundleUpdatePlan{}, err
		}
		candidateMetadataGenerated, err := parseCanonicalTrustMetadataTime(plan.Authentication.GeneratedAt, "candidate.authentication.generated_at")
		if err != nil {
			return TrustBundleUpdatePlan{}, err
		}
		if candidateMetadataGenerated.Before(currentMetadataGenerated) {
			return TrustBundleUpdatePlan{}, errors.New("FFU trust update candidate metadata generation time precedes current metadata")
		}
		candidatePlan = &plan
	}

	added, removed, replaced, addedDistrust, removedDistrust, emergency := trustUpdateDelta(currentPlan, candidatePlan)
	operationPayloadDigest := sha256.Sum256(verifiedOperation.canonical)
	operationEnvelopeDigest := sha256.Sum256(operationData)
	currentExpired := trustUpdateMetadataExpired(currentPlan, evaluationTime)

	plan := TrustBundleUpdatePlan{
		Schema:                       trustUpdateSchema,
		Purpose:                      trustUpdatePurpose,
		Action:                       verifiedOperation.document.Action,
		Sequence:                     verifiedOperation.document.Sequence,
		GeneratedAt:                  verifiedOperation.document.GeneratedAt,
		ExpiresAt:                    verifiedOperation.document.ExpiresAt,
		EvaluationTime:               evaluationTime.UTC().Format(time.RFC3339),
		CurrentGeneration:            active.record.Generation,
		CurrentSequence:              active.record.Sequence,
		CurrentBundleSHA256:          active.record.BundleSHA256,
		CurrentEnvelopeSHA256:        active.record.EnvelopeSHA256,
		CurrentEvidenceSHA256:        active.record.EvidenceSHA256,
		CurrentPublicationPlanSHA256: active.record.PlanSHA256,
		CurrentReproducedPlanSHA256:  currentPlan.PlanSHA256,
		CurrentPublicationTime:       publicationTime.UTC().Format(time.RFC3339),
		CurrentBundleExpiresAt:       currentPlan.ExpiresAt,
		CurrentMetadataExpiresAt:     currentPlan.Authentication.ExpiresAt,
		CurrentBundleExpired:         trustUpdateTimeExpired(currentPlan.ExpiresAt, evaluationTime),
		CurrentMetadataExpired:       currentExpired,
		CurrentKeySetVersion:         currentVerified.version,
		CurrentKeySetSHA256:          currentVerified.sha256,
		CurrentThreshold:             currentVerified.threshold,
		CurrentSigningKeyIDs:         append([]string(nil), currentPlan.Authentication.SigningKeyIDs...),
		NextKeySetVersion:            nextVerified.version,
		NextKeySetSHA256:             nextVerified.sha256,
		NextThreshold:                nextVerified.threshold,
		PolicyRotated:                verifiedOperation.rotated,
		OperationSigningKeyIDs:       append([]string(nil), verifiedOperation.currentKeyIDs...),
		ReplacementSigningKeyIDs:     append([]string(nil), verifiedOperation.replacementIDs...),
		OperationPayloadSHA256:       hex.EncodeToString(operationPayloadDigest[:]),
		OperationEnvelopeSHA256:      hex.EncodeToString(operationEnvelopeDigest[:]),
		CandidateBundleSize:          verifiedOperation.document.CandidateBundleSize,
		CandidateBundleSHA256:        verifiedOperation.document.CandidateBundleSHA256,
		CandidateMetadataSize:        verifiedOperation.document.CandidateMetadataSize,
		CandidateMetadataSHA256:      verifiedOperation.document.CandidateMetadataSHA256,
		AddedRoots:                   added,
		RemovedRoots:                 removed,
		ReplacedRoots:                replaced,
		AddedDistrustSHA256:          addedDistrust,
		RemovedDistrustSHA256:        removedDistrust,
		EmergencyDistrustSHA256:      emergency,
		CurrentStateValidated:        true,
		OperationAuthenticated:       true,
		ReplacementPolicyAuthorized:  !verifiedOperation.rotated || len(verifiedOperation.replacementIDs) >= nextVerified.threshold,
		CandidateAuthenticated:       candidatePlan != nil,
		PublicationPerformed:         false,
		WithdrawalPerformed:          false,
		TrustAnchorsActivated:        false,
		HostTLSStoreConsulted:        false,
		CertificateChainBuilt:        false,
		PublisherTrusted:             false,
		CurrentAuthentication:        cloneTrustBundleAuthentication(currentPlan.Authentication),
		Limitations: []string{
			"the signed operation and exact candidate bytes are authenticated and reported, but no trust-store mutation is performed",
			"withdrawal and publication require a later descriptor-bound transaction that consumes this exact plan",
			"current durable state may be historically verified after metadata expiry only to authorize replacement or withdrawal",
			"trust-anchor activation, certificate-chain construction, publisher trust, host TLS fallback, network retrieval, target access, and execution remain separate",
		},
	}
	if candidatePlan != nil {
		plan.CandidatePlanSHA256 = candidatePlan.PlanSHA256
		plan.CandidateBundleExpiresAt = candidatePlan.ExpiresAt
		plan.CandidateMetadataExpiresAt = candidatePlan.Authentication.ExpiresAt
		plan.CandidateSigningKeyIDs = append([]string(nil), candidatePlan.Authentication.SigningKeyIDs...)
		plan.CandidateAuthentication = cloneTrustBundleAuthentication(candidatePlan.Authentication)
	}
	plan.PlanSHA256 = trustBundleUpdatePlanDigest(plan)

	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, active); err != nil {
		return TrustBundleUpdatePlan{}, err
	}
	return plan, nil
}

func loadTrustUpdateCurrentState(ctx context.Context, root, generations *os.File, policy TrustMetadataPolicy) (trustStoreActiveSnapshot, TrustBundlePlan, time.Time, error) {
	active, err := readTrustStoreActive(root)
	if errors.Is(err, os.ErrNotExist) {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, nil
	}
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	if err := validateTrustStoreActiveRecord(active.record); err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	generation, err := openTrustStoreDirectory(generations, active.record.Generation)
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	evidenceData, _, readErr := readTrustStoreRegular(generation, trustStoreEvidenceName, maxTrustStoreEvidenceBytes, 0o400)
	closeErr := generation.Close()
	if readErr != nil || closeErr != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, errors.Join(readErr, closeErr)
	}
	evidence, err := parseTrustStoreEvidence(evidenceData)
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	publicationTime, err := parseCanonicalTrustMetadataTime(evidence.PublicationEvaluationTime, "publication_evaluation_time")
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	plan, err := loadTrustStoreGeneration(ctx, generations, active.record, policy, publicationTime)
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, fmt.Errorf("validate current FFU trust update generation: %w", err)
	}
	if err := verifyTrustStoreActiveSnapshot(root, active); err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, time.Time{}, err
	}
	return active, plan, publicationTime, nil
}

func verifyTrustUpdateOperation(
	data []byte,
	active TrustStoreActiveRecord,
	currentPlan TrustBundlePlan,
	publicationTime time.Time,
	currentPolicy verifiedTrustMetadataPolicy,
	nextPolicy verifiedTrustMetadataPolicy,
	candidateBundle []byte,
	candidateMetadata []byte,
	evaluationTime time.Time,
) (verifiedTrustUpdateOperation, error) {
	if err := rejectDuplicateTrustMetadataJSONMembers(data); err != nil {
		return verifiedTrustUpdateOperation{}, fmt.Errorf("validate FFU trust update JSON members: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope TrustUpdateOperationEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return verifiedTrustUpdateOperation{}, fmt.Errorf("decode FFU trust update envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return verifiedTrustUpdateOperation{}, errors.New("FFU trust update envelope contains multiple JSON values")
	}
	if len(envelope.Signed) == 0 {
		return verifiedTrustUpdateOperation{}, errors.New("FFU trust update signed payload is empty")
	}
	if len(envelope.Signatures) == 0 || len(envelope.Signatures) > maxTrustUpdateSignatures {
		return verifiedTrustUpdateOperation{}, fmt.Errorf("FFU trust update envelope must contain between 1 and %d signatures", maxTrustUpdateSignatures)
	}

	signedDecoder := json.NewDecoder(bytes.NewReader(envelope.Signed))
	signedDecoder.DisallowUnknownFields()
	var document TrustUpdateOperationDocument
	if err := signedDecoder.Decode(&document); err != nil {
		return verifiedTrustUpdateOperation{}, fmt.Errorf("decode FFU trust update signed payload: %w", err)
	}
	if err := signedDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return verifiedTrustUpdateOperation{}, errors.New("FFU trust update signed payload contains multiple JSON values")
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return verifiedTrustUpdateOperation{}, err
	}
	if !bytes.Equal(canonical, envelope.Signed) {
		return verifiedTrustUpdateOperation{}, errors.New("FFU trust update signed payload is not canonical JSON")
	}

	rotated, err := validateTrustUpdateDocument(document, active, currentPlan, publicationTime, currentPolicy, nextPolicy, candidateBundle, candidateMetadata, evaluationTime)
	if err != nil {
		return verifiedTrustUpdateOperation{}, err
	}
	currentIDs, replacementIDs, err := verifyTrustUpdateSignatures(envelope.Signatures, currentPolicy, nextPolicy, canonical, rotated)
	if err != nil {
		return verifiedTrustUpdateOperation{}, err
	}
	return verifiedTrustUpdateOperation{document: document, canonical: canonical, currentKeyIDs: currentIDs, replacementIDs: replacementIDs, rotated: rotated}, nil
}

func validateTrustUpdateDocument(
	document TrustUpdateOperationDocument,
	active TrustStoreActiveRecord,
	currentPlan TrustBundlePlan,
	publicationTime time.Time,
	currentPolicy verifiedTrustMetadataPolicy,
	nextPolicy verifiedTrustMetadataPolicy,
	candidateBundle []byte,
	candidateMetadata []byte,
	evaluationTime time.Time,
) (bool, error) {
	if document.Schema != trustUpdateSchema || document.Purpose != trustUpdatePurpose {
		return false, errors.New("FFU trust update schema or purpose is invalid")
	}
	if document.Action != trustUpdateActionPublish && document.Action != trustUpdateActionWithdraw {
		return false, fmt.Errorf("unsupported FFU trust update action %q", document.Action)
	}
	if document.Sequence <= active.Sequence {
		return false, fmt.Errorf("FFU trust update sequence %d must exceed current sequence %d", document.Sequence, active.Sequence)
	}
	generatedAt, err := parseCanonicalTrustMetadataTime(document.GeneratedAt, "update.generated_at")
	if err != nil {
		return false, err
	}
	expiresAt, err := parseCanonicalTrustMetadataTime(document.ExpiresAt, "update.expires_at")
	if err != nil {
		return false, err
	}
	if !expiresAt.After(generatedAt) || expiresAt.Sub(generatedAt) > maxFFUTrustMetadataLifetime {
		return false, errors.New("FFU trust update validity interval is invalid")
	}
	evaluationTime = evaluationTime.UTC()
	if evaluationTime.Before(generatedAt) || !evaluationTime.Before(expiresAt) {
		return false, errors.New("FFU trust update operation is not valid at the evaluation time")
	}
	if generatedAt.Before(publicationTime.UTC()) {
		return false, errors.New("FFU trust update operation predates the current durable publication")
	}
	if document.CurrentGeneration != active.Generation || document.CurrentSequence != active.Sequence || document.CurrentBundleSHA256 != active.BundleSHA256 || document.CurrentEnvelopeSHA256 != active.EnvelopeSHA256 || document.CurrentEvidenceSHA256 != active.EvidenceSHA256 || document.CurrentPublicationPlanSHA256 != active.PlanSHA256 {
		return false, errors.New("FFU trust update current-state binding does not match durable active state")
	}
	if currentPlan.Authentication == nil || document.CurrentKeySetVersion != currentPolicy.version || document.CurrentKeySetSHA256 != currentPolicy.sha256 || document.CurrentThreshold != currentPolicy.threshold {
		return false, errors.New("FFU trust update current-policy binding is invalid")
	}
	if document.NextKeySetVersion != nextPolicy.version || document.NextKeySetSHA256 != nextPolicy.sha256 || document.NextThreshold != nextPolicy.threshold {
		return false, errors.New("FFU trust update replacement-policy binding is invalid")
	}

	rotated := currentPolicy.version != nextPolicy.version || currentPolicy.sha256 != nextPolicy.sha256 || currentPolicy.threshold != nextPolicy.threshold
	if rotated {
		if document.Action != trustUpdateActionPublish {
			return false, errors.New("FFU trust update policy rotation requires a publish action")
		}
		if nextPolicy.version != currentPolicy.version+1 {
			return false, fmt.Errorf("FFU trust update replacement policy version must advance exactly from %d to %d", currentPolicy.version, currentPolicy.version+1)
		}
		if nextPolicy.sha256 == currentPolicy.sha256 {
			return false, errors.New("FFU trust update replacement policy version changed without changing policy content")
		}
	} else if nextPolicy.version != currentPolicy.version || nextPolicy.sha256 != currentPolicy.sha256 || nextPolicy.threshold != currentPolicy.threshold {
		return false, errors.New("FFU trust update unchanged policy must be identical")
	}

	switch document.Action {
	case trustUpdateActionPublish:
		if len(candidateBundle) == 0 || len(candidateMetadata) == 0 {
			return false, errors.New("FFU trust update publish action requires candidate bundle and metadata bytes")
		}
		if int64(len(candidateBundle)) > maxFFUTrustBundleBytes || len(candidateMetadata) > maxFFUTrustMetadataBytes {
			return false, errors.New("FFU trust update candidate exceeds bounded size limits")
		}
		bundleDigest := sha256.Sum256(candidateBundle)
		metadataDigest := sha256.Sum256(candidateMetadata)
		if document.CandidateBundleSize != uint64(len(candidateBundle)) || document.CandidateBundleSHA256 != hex.EncodeToString(bundleDigest[:]) || document.CandidateMetadataSize != uint64(len(candidateMetadata)) || document.CandidateMetadataSHA256 != hex.EncodeToString(metadataDigest[:]) {
			return false, errors.New("FFU trust update candidate byte binding does not match supplied bytes")
		}
	case trustUpdateActionWithdraw:
		if len(candidateBundle) != 0 || len(candidateMetadata) != 0 || document.CandidateBundleSize != 0 || document.CandidateBundleSHA256 != "" || document.CandidateMetadataSize != 0 || document.CandidateMetadataSHA256 != "" {
			return false, errors.New("FFU trust update withdrawal must not carry candidate bundle or metadata bytes")
		}
	}
	return rotated, nil
}

func verifyTrustUpdateSignatures(signatures []TrustUpdateSignature, currentPolicy, nextPolicy verifiedTrustMetadataPolicy, canonical []byte, rotated bool) ([]string, []string, error) {
	union := make(map[string]ed25519.PublicKey, len(currentPolicy.keys)+len(nextPolicy.keys))
	for id, key := range currentPolicy.keys {
		union[id] = key
	}
	for id, key := range nextPolicy.keys {
		if existing, ok := union[id]; ok && !bytes.Equal(existing, key) {
			return nil, nil, fmt.Errorf("FFU trust update key %q differs across authorization policies", id)
		}
		union[id] = key
	}
	currentIDs := make([]string, 0, len(signatures))
	nextIDs := make([]string, 0, len(signatures))
	previous := ""
	seen := make(map[string]struct{}, len(signatures))
	for index, signature := range signatures {
		if signature.Algorithm != ffuTrustMetadataAlgorithm {
			return nil, nil, fmt.Errorf("FFU trust update signature %d uses unsupported algorithm %q", index, signature.Algorithm)
		}
		if !canonicalTrustMetadataKeyID(signature.KeyID) {
			return nil, nil, fmt.Errorf("FFU trust update signature %d has invalid key id %q", index, signature.KeyID)
		}
		if previous != "" && signature.KeyID <= previous {
			return nil, nil, errors.New("FFU trust update signatures must be sorted and distinct by key id")
		}
		previous = signature.KeyID
		if _, exists := seen[signature.KeyID]; exists {
			return nil, nil, fmt.Errorf("FFU trust update repeats signature for key %q", signature.KeyID)
		}
		seen[signature.KeyID] = struct{}{}
		key, ok := union[signature.KeyID]
		if !ok {
			return nil, nil, fmt.Errorf("FFU trust update signature references unknown key %q", signature.KeyID)
		}
		signatureBytes, err := decodeCanonicalTrustMetadataBase64(signature.Signature, ed25519.SignatureSize, fmt.Sprintf("FFU trust update signature for key %q", signature.KeyID))
		if err != nil {
			return nil, nil, err
		}
		if !ed25519.Verify(key, canonical, signatureBytes) {
			return nil, nil, fmt.Errorf("verify FFU trust update signature for key %q", signature.KeyID)
		}
		if _, ok := currentPolicy.keys[signature.KeyID]; ok {
			currentIDs = append(currentIDs, signature.KeyID)
		}
		if _, ok := nextPolicy.keys[signature.KeyID]; ok {
			nextIDs = append(nextIDs, signature.KeyID)
		}
	}
	if len(currentIDs) < currentPolicy.threshold {
		return nil, nil, fmt.Errorf("FFU trust update current threshold requires %d valid keys, found %d", currentPolicy.threshold, len(currentIDs))
	}
	if rotated && len(nextIDs) < nextPolicy.threshold {
		return nil, nil, fmt.Errorf("FFU trust update replacement threshold requires %d valid keys, found %d", nextPolicy.threshold, len(nextIDs))
	}
	if !rotated {
		nextIDs = nil
	}
	return currentIDs, nextIDs, nil
}

func trustUpdateDelta(current TrustBundlePlan, candidate *TrustBundlePlan) ([]TrustAnchor, []TrustAnchor, []TrustRootReplacement, []string, []string, []string) {
	currentByID := make(map[string]TrustAnchor, len(current.Roots))
	for _, root := range current.Roots {
		currentByID[root.ID] = root
	}
	candidateRoots := []TrustAnchor(nil)
	candidateDistrust := append([]string(nil), current.DistrustedSHA256...)
	if candidate != nil {
		candidateRoots = candidate.Roots
		candidateDistrust = candidate.DistrustedSHA256
	}
	candidateByID := make(map[string]TrustAnchor, len(candidateRoots))
	for _, root := range candidateRoots {
		candidateByID[root.ID] = root
	}
	added := make([]TrustAnchor, 0)
	removed := make([]TrustAnchor, 0)
	replaced := make([]TrustRootReplacement, 0)
	for _, root := range current.Roots {
		next, ok := candidateByID[root.ID]
		switch {
		case !ok:
			removed = append(removed, root)
		case next.CertificateSHA256 != root.CertificateSHA256:
			replaced = append(replaced, TrustRootReplacement{ID: root.ID, Before: root, After: next})
		}
	}
	for _, root := range candidateRoots {
		if _, ok := currentByID[root.ID]; !ok {
			added = append(added, root)
		}
	}

	currentDistrustSet := make(map[string]struct{}, len(current.DistrustedSHA256))
	for _, value := range current.DistrustedSHA256 {
		currentDistrustSet[value] = struct{}{}
	}
	candidateDistrustSet := make(map[string]struct{}, len(candidateDistrust))
	for _, value := range candidateDistrust {
		candidateDistrustSet[value] = struct{}{}
	}
	addedDistrust := make([]string, 0)
	removedDistrust := make([]string, 0)
	for _, value := range candidateDistrust {
		if _, ok := currentDistrustSet[value]; !ok {
			addedDistrust = append(addedDistrust, value)
		}
	}
	for _, value := range current.DistrustedSHA256 {
		if _, ok := candidateDistrustSet[value]; !ok {
			removedDistrust = append(removedDistrust, value)
		}
	}
	candidateFingerprints := make(map[string]struct{}, len(candidateRoots))
	for _, root := range candidateRoots {
		candidateFingerprints[root.CertificateSHA256] = struct{}{}
	}
	emergency := make([]string, 0)
	for _, root := range current.Roots {
		if _, remains := candidateFingerprints[root.CertificateSHA256]; remains {
			continue
		}
		if _, distrusted := candidateDistrustSet[root.CertificateSHA256]; distrusted {
			emergency = append(emergency, root.CertificateSHA256)
		}
	}
	sort.Strings(addedDistrust)
	sort.Strings(removedDistrust)
	sort.Strings(emergency)
	return added, removed, replaced, addedDistrust, removedDistrust, emergency
}

func trustUpdateMetadataExpired(plan TrustBundlePlan, evaluationTime time.Time) bool {
	if plan.Authentication == nil {
		return true
	}
	return trustUpdateTimeExpired(plan.Authentication.ExpiresAt, evaluationTime)
}

func trustUpdateTimeExpired(value string, evaluationTime time.Time) bool {
	expires, err := parseCanonicalTrustMetadataTime(value, "expires_at")
	return err != nil || !evaluationTime.UTC().Before(expires)
}

func trustBundleUpdatePlanDigest(plan TrustBundleUpdatePlan) string {
	digest := sha256.New()
	writeTrustUint64(digest, uint64(plan.Schema))
	writeTrustString(digest, plan.Purpose)
	writeTrustString(digest, plan.Action)
	writeTrustUint64(digest, plan.Sequence)
	writeTrustString(digest, plan.GeneratedAt)
	writeTrustString(digest, plan.ExpiresAt)
	writeTrustString(digest, plan.EvaluationTime)
	writeTrustString(digest, plan.CurrentGeneration)
	writeTrustUint64(digest, plan.CurrentSequence)
	writeTrustString(digest, plan.CurrentBundleSHA256)
	writeTrustString(digest, plan.CurrentEnvelopeSHA256)
	writeTrustString(digest, plan.CurrentEvidenceSHA256)
	writeTrustString(digest, plan.CurrentPublicationPlanSHA256)
	writeTrustString(digest, plan.CurrentReproducedPlanSHA256)
	writeTrustString(digest, plan.CurrentPublicationTime)
	writeTrustString(digest, plan.CurrentBundleExpiresAt)
	writeTrustString(digest, plan.CurrentMetadataExpiresAt)
	writeTrustBool(digest, plan.CurrentBundleExpired)
	writeTrustBool(digest, plan.CurrentMetadataExpired)
	writeTrustUint64(digest, plan.CurrentKeySetVersion)
	writeTrustString(digest, plan.CurrentKeySetSHA256)
	writeTrustUint64(digest, uint64(plan.CurrentThreshold))
	writeTrustUint64(digest, plan.NextKeySetVersion)
	writeTrustString(digest, plan.NextKeySetSHA256)
	writeTrustUint64(digest, uint64(plan.NextThreshold))
	writeTrustBool(digest, plan.PolicyRotated)
	writeTrustString(digest, plan.OperationPayloadSHA256)
	writeTrustString(digest, plan.OperationEnvelopeSHA256)
	writeTrustUint64(digest, plan.CandidateBundleSize)
	writeTrustString(digest, plan.CandidateBundleSHA256)
	writeTrustUint64(digest, plan.CandidateMetadataSize)
	writeTrustString(digest, plan.CandidateMetadataSHA256)
	writeTrustString(digest, plan.CandidatePlanSHA256)
	writeTrustString(digest, plan.CandidateBundleExpiresAt)
	writeTrustString(digest, plan.CandidateMetadataExpiresAt)
	for _, values := range [][]string{plan.CurrentSigningKeyIDs, plan.OperationSigningKeyIDs, plan.ReplacementSigningKeyIDs, plan.CandidateSigningKeyIDs} {
		writeTrustUint64(digest, uint64(len(values)))
		for _, value := range values {
			writeTrustString(digest, value)
		}
	}
	writeTrustUint64(digest, uint64(len(plan.AddedRoots)))
	for _, root := range plan.AddedRoots {
		writeTrustString(digest, root.ID)
		writeTrustString(digest, root.CertificateSHA256)
	}
	writeTrustUint64(digest, uint64(len(plan.RemovedRoots)))
	for _, root := range plan.RemovedRoots {
		writeTrustString(digest, root.ID)
		writeTrustString(digest, root.CertificateSHA256)
	}
	writeTrustUint64(digest, uint64(len(plan.ReplacedRoots)))
	for _, replacement := range plan.ReplacedRoots {
		writeTrustString(digest, replacement.ID)
		writeTrustString(digest, replacement.Before.CertificateSHA256)
		writeTrustString(digest, replacement.After.CertificateSHA256)
	}
	for _, values := range [][]string{plan.AddedDistrustSHA256, plan.RemovedDistrustSHA256, plan.EmergencyDistrustSHA256} {
		writeTrustUint64(digest, uint64(len(values)))
		for _, value := range values {
			writeTrustString(digest, value)
		}
	}
	writeTrustBool(digest, plan.CurrentStateValidated)
	writeTrustBool(digest, plan.OperationAuthenticated)
	writeTrustBool(digest, plan.ReplacementPolicyAuthorized)
	writeTrustBool(digest, plan.CandidateAuthenticated)
	writeTrustBool(digest, plan.PublicationPerformed)
	writeTrustBool(digest, plan.WithdrawalPerformed)
	writeTrustBool(digest, plan.TrustAnchorsActivated)
	writeTrustBool(digest, plan.HostTLSStoreConsulted)
	writeTrustBool(digest, plan.CertificateChainBuilt)
	writeTrustBool(digest, plan.PublisherTrusted)
	return hex.EncodeToString(digest.Sum(nil))
}
