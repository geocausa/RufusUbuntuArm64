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
	"fmt"
	"os"
	"time"
)

// TrustUpdateApplyOptions exposes only a package-private interruption hook.
// Production callers cannot skip authentication, durability, or verification.
type TrustUpdateApplyOptions struct {
	hook func(stage string) error
}

// TrustBundleUpdateExecutionResult reports one committed signed publish or
// withdrawal operation. The authorization plan remains the exact pre-mutation
// plan that operators signed and reviewed; execution state is reported
// separately.
type TrustBundleUpdateExecutionResult struct {
	Root                  string                 `json:"root"`
	Generation            string                 `json:"generation"`
	PreviousGeneration    string                 `json:"previous_generation"`
	Active                TrustStoreActiveRecord `json:"active"`
	AuthorizationPlan     TrustBundleUpdatePlan  `json:"authorization_plan"`
	PublishedPlan         TrustBundlePlan        `json:"published_plan"`
	PublicationPerformed  bool                   `json:"publication_performed"`
	WithdrawalPerformed   bool                   `json:"withdrawal_performed"`
	TrustAnchorsActivated bool                   `json:"trust_anchors_activated"`
}

// ApplyAuthenticatedTrustBundlePublishOperation executes one signed publish
// operation while holding the trust-store root lock across authentication and
// commit. Withdrawal is handled by a separate tombstone transaction and is
// refused here.
func ApplyAuthenticatedTrustBundlePublishOperation(
	ctx context.Context,
	root string,
	operationData []byte,
	currentPolicy TrustMetadataPolicy,
	nextPolicy TrustMetadataPolicy,
	candidateBundle []byte,
	candidateMetadata []byte,
	evaluationTime time.Time,
	opts TrustUpdateApplyOptions,
) (result TrustBundleUpdateExecutionResult, returnErr error) {
	if ctx == nil {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update apply context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if evaluationTime.IsZero() {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update apply evaluation time is zero")
	}
	if len(operationData) == 0 || len(operationData) > maxTrustUpdateBytes {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update apply operation size is invalid")
	}
	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("current FFU trust update policy: %w", err)
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("replacement FFU trust update policy: %w", err)
	}
	currentPolicyData, err := canonicalTrustMetadataPolicyBytes(currentPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	nextPolicyData, err := canonicalTrustMetadataPolicyBytes(nextPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	defer rootFile.Close()
	generations, err := openTrustStoreDirectory(rootFile, trustStoreGenerationsName)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	state, err := planAuthenticatedTrustBundleOperationOpen(
		ctx, resolved, rootFile, rootIdentity, generations, generationsIdentity,
		operationData, currentPolicy, nextPolicy, currentVerified, nextVerified,
		candidateBundle, candidateMetadata, evaluationTime,
	)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if state.plan.Action != trustUpdateActionPublish || state.candidatePlan == nil {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update apply accepts signed publish operations only")
	}
	if !state.plan.CurrentStateValidated || !state.plan.OperationAuthenticated || !state.plan.CandidateAuthenticated || state.plan.PublicationPerformed || state.plan.WithdrawalPerformed || state.plan.TrustAnchorsActivated || state.plan.CertificateChainBuilt || state.plan.PublisherTrusted {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update apply received an invalid authorization plan")
	}
	if err := trustUpdateApplyStage(ctx, opts, "authorized"); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, state.active); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	candidatePlan := *state.candidatePlan
	envelopeDigest := sha256.Sum256(candidateMetadata)
	generation := trustStoreGenerationName(candidatePlan.Sequence, candidatePlan.BundleSHA256, hex.EncodeToString(envelopeDigest[:]))
	evidenceData, active, activeData, err := buildTrustStoreUpdateRecords(
		generation, candidateBundle, candidateMetadata, operationData,
		currentPolicyData, nextPolicyData, state,
	)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	transaction := &trustStoreTransaction{
		root:             rootFile,
		generations:      generations,
		generationFinal:  generation,
		activeWasPresent: true,
		activeNew:        active,
		previous:         state.active,
	}
	defer func() {
		if returnErr == nil {
			return
		}
		if rollbackErr := rollbackTrustStoreTransaction(transaction); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback signed FFU trust update publication: %w", rollbackErr))
		}
	}()

	existing, err := trustStoreExactEntry(generations, generation)
	switch {
	case err == nil:
		_ = existing
		loaded, loadErr := loadTrustStoreGeneration(ctx, generations, active, nextPolicy, evaluationTime)
		if loadErr != nil {
			return TrustBundleUpdateExecutionResult{}, fmt.Errorf("existing signed FFU trust update generation is invalid: %w", loadErr)
		}
		if loaded.PlanSHA256 != candidatePlan.PlanSHA256 {
			return TrustBundleUpdateExecutionResult{}, errors.New("existing signed FFU trust update generation has a different candidate plan")
		}
	case errors.Is(err, os.ErrNotExist):
		tempName, tempDirectory, createErr := createTrustStoreGenerationTemporary(generations)
		if createErr != nil {
			return TrustBundleUpdateExecutionResult{}, createErr
		}
		transaction.generationTemp = tempName
		if err := trustUpdateApplyStage(ctx, opts, "generation-created"); err != nil {
			tempDirectory.Close()
			return TrustBundleUpdateExecutionResult{}, err
		}
		writeErr := writeTrustStoreFile(tempDirectory, trustStoreBundleName, candidateBundle, 0o400)
		if writeErr == nil {
			writeErr = trustUpdateApplyStage(ctx, opts, "bundle-staged")
		}
		if writeErr == nil {
			writeErr = writeTrustStoreFile(tempDirectory, trustStoreEnvelopeName, candidateMetadata, 0o400)
		}
		if writeErr == nil {
			writeErr = trustUpdateApplyStage(ctx, opts, "metadata-staged")
		}
		if writeErr == nil {
			writeErr = writeTrustStoreFile(tempDirectory, trustStoreEvidenceName, evidenceData, 0o400)
		}
		if writeErr == nil {
			writeErr = trustUpdateApplyStage(ctx, opts, "evidence-staged")
		}
		if writeErr == nil {
			writeErr = tempDirectory.Chmod(0o500)
		}
		if writeErr == nil {
			writeErr = syncTrustStoreDirectory(tempDirectory)
		}
		closeErr := tempDirectory.Close()
		if writeErr != nil || closeErr != nil {
			return TrustBundleUpdateExecutionResult{}, errors.Join(writeErr, closeErr)
		}
		if err := trustUpdateApplyStage(ctx, opts, "generation-synced"); err != nil {
			return TrustBundleUpdateExecutionResult{}, err
		}
		if err := trustStoreRenameNoReplace(generations, tempName, generation); err != nil {
			return TrustBundleUpdateExecutionResult{}, fmt.Errorf("publish signed FFU trust update generation: %w", err)
		}
		transaction.generationTemp = ""
		transaction.generationAdded = true
		if err := syncTrustStoreDirectory(generations); err != nil {
			return TrustBundleUpdateExecutionResult{}, err
		}
		if err := trustUpdateApplyStage(ctx, opts, "generation-published"); err != nil {
			return TrustBundleUpdateExecutionResult{}, err
		}
	default:
		return TrustBundleUpdateExecutionResult{}, err
	}

	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, state.active); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	activeTemp, err := writeTrustStoreTemporary(rootFile, trustStoreTempActive, activeData, 0o600)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	transaction.activeTemp = activeTemp
	if err := trustUpdateApplyStage(ctx, opts, "active-staged"); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := trustStoreRenameExchange(rootFile, activeTemp, trustStoreActiveName); err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("exchange signed FFU trust update active record: %w", err)
	}
	transaction.activeCommitted = true
	oldData, oldIdentity, err := readTrustStoreRegular(rootFile, activeTemp, maxTrustStoreActiveBytes, 0o600)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if !sameTrustStoreContentObject(oldIdentity, state.active.identity) || !bytes.Equal(oldData, state.active.data) {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust update active record changed before atomic exchange")
	}
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := trustUpdateApplyStage(ctx, opts, "active-committed"); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	loaded, err := loadTrustStoreGeneration(ctx, generations, active, nextPolicy, evaluationTime)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("verify committed signed FFU trust update generation: %w", err)
	}
	current, err := readTrustStoreActive(rootFile)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if !current.exists || current.record != active {
		return TrustBundleUpdateExecutionResult{}, errors.New("signed FFU trust update active record changed before verification")
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, current); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := trustUpdateApplyStage(ctx, opts, "verified"); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := removeTrustStoreExact(rootFile, transaction.activeTemp); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	transaction.activeTemp = ""
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	transaction.activeCommitted = false
	transaction.generationAdded = false

	return TrustBundleUpdateExecutionResult{
		Root:                  resolved,
		Generation:            generation,
		PreviousGeneration:    state.active.record.Generation,
		Active:                active,
		AuthorizationPlan:     state.plan,
		PublishedPlan:         loaded,
		PublicationPerformed:  true,
		WithdrawalPerformed:   false,
		TrustAnchorsActivated: false,
	}, nil
}

func buildTrustStoreUpdateRecords(
	generation string,
	bundleData []byte,
	envelopeData []byte,
	operationData []byte,
	currentPolicyData []byte,
	nextPolicyData []byte,
	state trustBundleUpdatePlanningState,
) ([]byte, TrustStoreActiveRecord, []byte, error) {
	if state.candidatePlan == nil || state.candidatePlan.Authentication == nil {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("signed FFU trust update has no candidate authentication evidence")
	}
	candidatePlan := *state.candidatePlan
	envelopeDigest := sha256.Sum256(envelopeData)
	operationDigest := sha256.Sum256(operationData)
	currentPolicyDigest := sha256.Sum256(currentPolicyData)
	nextPolicyDigest := sha256.Sum256(nextPolicyData)
	evidence := TrustStoreGenerationEvidence{
		Schema:                    trustStoreSchema,
		Purpose:                   trustStoreUpdateGenerationPurpose,
		Generation:                generation,
		Sequence:                  candidatePlan.Sequence,
		BundleSize:                uint64(len(bundleData)),
		BundleSHA256:              candidatePlan.BundleSHA256,
		EnvelopeSize:              uint64(len(envelopeData)),
		EnvelopeSHA256:            hex.EncodeToString(envelopeDigest[:]),
		SignedMetadataSHA256:      candidatePlan.Authentication.MetadataSHA256,
		PlanSHA256:                candidatePlan.PlanSHA256,
		KeySetVersion:             candidatePlan.Authentication.KeySetVersion,
		KeySetSHA256:              candidatePlan.Authentication.KeySetSHA256,
		Threshold:                 candidatePlan.Authentication.Threshold,
		SigningKeyIDs:             append([]string(nil), candidatePlan.Authentication.SigningKeyIDs...),
		PreviousSequence:          state.active.record.Sequence,
		PreviousBundleSHA256:      state.active.record.BundleSHA256,
		PublicationEvaluationTime: state.plan.EvaluationTime,
		TrustAnchorsActivated:     false,
		UpdatePlanSHA256:          state.plan.PlanSHA256,
		OperationSize:             uint64(len(operationData)),
		OperationSHA256:           hex.EncodeToString(operationDigest[:]),
		OperationBase64:           base64.StdEncoding.EncodeToString(operationData),
		CurrentPolicySize:         uint64(len(currentPolicyData)),
		CurrentPolicySHA256:       hex.EncodeToString(currentPolicyDigest[:]),
		CurrentPolicyBase64:       base64.StdEncoding.EncodeToString(currentPolicyData),
		NextPolicySize:            uint64(len(nextPolicyData)),
		NextPolicySHA256:          hex.EncodeToString(nextPolicyDigest[:]),
		NextPolicyBase64:          base64.StdEncoding.EncodeToString(nextPolicyData),
		PolicyRotated:             state.plan.PolicyRotated,
		OperationSigningKeyIDs:    append([]string(nil), state.plan.OperationSigningKeyIDs...),
		ReplacementSigningKeyIDs:  append([]string(nil), state.plan.ReplacementSigningKeyIDs...),
		PreviousGeneration:        state.active.record.Generation,
		PreviousEnvelopeSHA256:    state.active.record.EnvelopeSHA256,
		PreviousEvidenceSHA256:    state.active.record.EvidenceSHA256,
		PreviousPlanSHA256:        state.active.record.PlanSHA256,
		PreviousWithdrawn:         state.active.record.Withdrawn,
	}
	evidenceData, err := json.Marshal(evidence)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	evidenceDigest := sha256.Sum256(evidenceData)
	active := TrustStoreActiveRecord{
		Schema:         trustStoreSchema,
		Purpose:        trustStoreActivePurpose,
		Generation:     generation,
		Sequence:       candidatePlan.Sequence,
		BundleSHA256:   candidatePlan.BundleSHA256,
		EnvelopeSHA256: evidence.EnvelopeSHA256,
		EvidenceSHA256: hex.EncodeToString(evidenceDigest[:]),
		PlanSHA256:     candidatePlan.PlanSHA256,
	}
	activeData, err := json.Marshal(active)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	return evidenceData, active, activeData, nil
}

func canonicalTrustMetadataPolicyBytes(policy TrustMetadataPolicy) ([]byte, error) {
	if _, err := verifyTrustMetadataPolicy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

func trustUpdateApplyStage(ctx context.Context, opts TrustUpdateApplyOptions, stage string) error {
	if err := trustStoreContext(ctx); err != nil {
		return err
	}
	if opts.hook != nil {
		if err := opts.hook(stage); err != nil {
			return fmt.Errorf("injected signed FFU trust update failure at %s: %w", stage, err)
		}
	}
	return trustStoreContext(ctx)
}
