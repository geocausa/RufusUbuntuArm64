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

// ApplyAuthenticatedTrustBundleWithdrawalOperation executes one signed
// withdrawal operation while holding the trust-store root lock across
// authentication and commit. The previous immutable bundle and metadata remain
// available as historical evidence, but the new active record is an explicit
// tombstone that cannot be activated unless a later higher-sequence signed
// publish operation supersedes it.
func ApplyAuthenticatedTrustBundleWithdrawalOperation(
	ctx context.Context,
	root string,
	operationData []byte,
	currentPolicy TrustMetadataPolicy,
	nextPolicy TrustMetadataPolicy,
	evaluationTime time.Time,
	opts TrustUpdateApplyOptions,
) (result TrustBundleUpdateExecutionResult, returnErr error) {
	if ctx == nil {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if evaluationTime.IsZero() {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal evaluation time is zero")
	}
	if len(operationData) == 0 || len(operationData) > maxTrustUpdateBytes {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal operation size is invalid")
	}
	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("current FFU trust withdrawal policy: %w", err)
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("replacement FFU trust withdrawal policy: %w", err)
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
		nil, nil, evaluationTime,
	)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if state.active.record.Withdrawn {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust bundle is already withdrawn")
	}
	if state.plan.Action != trustUpdateActionWithdraw || state.candidatePlan != nil {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal accepts signed withdrawal operations only")
	}
	if state.plan.PolicyRotated || !bytes.Equal(currentPolicyData, nextPolicyData) {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal cannot rotate the authorization policy")
	}
	if !state.plan.CurrentStateValidated || !state.plan.OperationAuthenticated || state.plan.CandidateAuthenticated || state.plan.PublicationPerformed || state.plan.WithdrawalPerformed || state.plan.TrustAnchorsActivated || state.plan.CertificateChainBuilt || state.plan.PublisherTrusted {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal received an invalid authorization plan")
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

	bundleData, envelopeData, err := readTrustStoreWithdrawalPayload(ctx, generations, state.active.record)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, state.active); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	generation := trustStoreGenerationName(state.plan.Sequence, state.active.record.BundleSHA256, state.active.record.EnvelopeSHA256)
	evidenceData, active, activeData, err := buildTrustStoreWithdrawalRecords(
		generation, bundleData, envelopeData, operationData,
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
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback signed FFU trust withdrawal: %w", rollbackErr))
		}
	}()

	existing, err := trustStoreExactEntry(generations, generation)
	switch {
	case err == nil:
		_ = existing
		loaded, loadErr := loadTrustStoreGeneration(ctx, generations, active, nextPolicy, evaluationTime)
		if loadErr != nil {
			return TrustBundleUpdateExecutionResult{}, fmt.Errorf("existing signed FFU trust withdrawal generation is invalid: %w", loadErr)
		}
		if loaded.PlanSHA256 != state.currentPlan.PlanSHA256 {
			return TrustBundleUpdateExecutionResult{}, errors.New("existing signed FFU trust withdrawal generation has different historical evidence")
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
		writeErr := writeTrustStoreFile(tempDirectory, trustStoreBundleName, bundleData, 0o400)
		if writeErr == nil {
			writeErr = trustUpdateApplyStage(ctx, opts, "bundle-staged")
		}
		if writeErr == nil {
			writeErr = writeTrustStoreFile(tempDirectory, trustStoreEnvelopeName, envelopeData, 0o400)
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
			return TrustBundleUpdateExecutionResult{}, fmt.Errorf("publish signed FFU trust withdrawal generation: %w", err)
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
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("exchange signed FFU trust withdrawal active record: %w", err)
	}
	transaction.activeCommitted = true
	oldData, oldIdentity, err := readTrustStoreRegular(rootFile, activeTemp, maxTrustStoreActiveBytes, 0o600)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if !sameTrustStoreContentObject(oldIdentity, state.active.identity) || !bytes.Equal(oldData, state.active.data) {
		return TrustBundleUpdateExecutionResult{}, errors.New("FFU trust withdrawal active record changed before atomic exchange")
	}
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if err := trustUpdateApplyStage(ctx, opts, "active-committed"); err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}

	loaded, err := loadTrustStoreGeneration(ctx, generations, active, nextPolicy, evaluationTime)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, fmt.Errorf("verify committed signed FFU trust withdrawal generation: %w", err)
	}
	current, err := readTrustStoreActive(rootFile)
	if err != nil {
		return TrustBundleUpdateExecutionResult{}, err
	}
	if !current.exists || current.record != active {
		return TrustBundleUpdateExecutionResult{}, errors.New("signed FFU trust withdrawal active record changed before verification")
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
		PublicationPerformed:  false,
		WithdrawalPerformed:   true,
		TrustAnchorsActivated: false,
	}, nil
}

func readTrustStoreWithdrawalPayload(ctx context.Context, generations *os.File, active TrustStoreActiveRecord) ([]byte, []byte, error) {
	if active.Withdrawn {
		return nil, nil, errors.New("FFU trust bundle is already withdrawn")
	}
	generation, err := openTrustStoreDirectory(generations, active.Generation)
	if err != nil {
		return nil, nil, err
	}
	defer generation.Close()
	generationIdentity, err := trustStoreIdentityFromOpenFile(generation)
	if err != nil {
		return nil, nil, err
	}
	if os.FileMode(generationIdentity.mode).Perm() != 0o500 {
		return nil, nil, errors.New("FFU trust-store published generation mode must be 0500")
	}
	if err := validateTrustStoreGenerationEntries(generation); err != nil {
		return nil, nil, err
	}
	bundleData, bundleIdentity, err := readTrustStoreRegular(generation, trustStoreBundleName, int(maxFFUTrustBundleBytes), 0o400)
	if err != nil {
		return nil, nil, err
	}
	if err := trustStoreContext(ctx); err != nil {
		return nil, nil, err
	}
	envelopeData, envelopeIdentity, err := readTrustStoreRegular(generation, trustStoreEnvelopeName, maxFFUTrustMetadataBytes, 0o400)
	if err != nil {
		return nil, nil, err
	}
	evidenceData, evidenceIdentity, err := readTrustStoreRegular(generation, trustStoreEvidenceName, maxTrustStoreEvidenceBytes, 0o400)
	if err != nil {
		return nil, nil, err
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	evidenceDigest := sha256.Sum256(evidenceData)
	if hex.EncodeToString(bundleDigest[:]) != active.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != active.EnvelopeSHA256 || hex.EncodeToString(evidenceDigest[:]) != active.EvidenceSHA256 {
		return nil, nil, errors.New("FFU trust withdrawal source generation does not match the active record")
	}
	for _, snapshot := range []struct {
		name     string
		identity trustStoreFileIdentity
		maximum  int
	}{
		{trustStoreBundleName, bundleIdentity, int(maxFFUTrustBundleBytes)},
		{trustStoreEnvelopeName, envelopeIdentity, maxFFUTrustMetadataBytes},
		{trustStoreEvidenceName, evidenceIdentity, maxTrustStoreEvidenceBytes},
	} {
		if err := verifyTrustStoreRegularSnapshot(generation, snapshot.name, snapshot.identity, snapshot.maximum, 0o400); err != nil {
			return nil, nil, err
		}
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(generations, active.Generation, generationIdentity); err != nil {
		return nil, nil, err
	}
	return bundleData, envelopeData, nil
}

func buildTrustStoreWithdrawalRecords(
	generation string,
	bundleData []byte,
	envelopeData []byte,
	operationData []byte,
	currentPolicyData []byte,
	nextPolicyData []byte,
	state trustBundleUpdatePlanningState,
) ([]byte, TrustStoreActiveRecord, []byte, error) {
	if state.currentPlan.Authentication == nil || state.active.record.Withdrawn {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("signed FFU trust withdrawal has no active authentication evidence")
	}
	if state.plan.Action != trustUpdateActionWithdraw || state.plan.PolicyRotated || state.candidatePlan != nil || !bytes.Equal(currentPolicyData, nextPolicyData) {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("signed FFU trust withdrawal authorization plan is invalid")
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	if hex.EncodeToString(bundleDigest[:]) != state.active.record.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != state.active.record.EnvelopeSHA256 {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("signed FFU trust withdrawal historical bytes do not match active state")
	}
	operationDigest := sha256.Sum256(operationData)
	currentPolicyDigest := sha256.Sum256(currentPolicyData)
	nextPolicyDigest := sha256.Sum256(nextPolicyData)
	evidence := TrustStoreGenerationEvidence{
		Schema:                    trustStoreSchema,
		Purpose:                   trustStoreWithdrawalGenerationPurpose,
		Generation:                generation,
		Sequence:                  state.plan.Sequence,
		BundleSize:                uint64(len(bundleData)),
		BundleSHA256:              state.active.record.BundleSHA256,
		EnvelopeSize:              uint64(len(envelopeData)),
		EnvelopeSHA256:            state.active.record.EnvelopeSHA256,
		SignedMetadataSHA256:      state.currentPlan.Authentication.MetadataSHA256,
		PlanSHA256:                state.currentPlan.PlanSHA256,
		KeySetVersion:             state.currentPlan.Authentication.KeySetVersion,
		KeySetSHA256:              state.currentPlan.Authentication.KeySetSHA256,
		Threshold:                 state.currentPlan.Authentication.Threshold,
		SigningKeyIDs:             append([]string(nil), state.currentPlan.Authentication.SigningKeyIDs...),
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
		PolicyRotated:             false,
		OperationSigningKeyIDs:    append([]string(nil), state.plan.OperationSigningKeyIDs...),
		PreviousGeneration:        state.active.record.Generation,
		PreviousEnvelopeSHA256:    state.active.record.EnvelopeSHA256,
		PreviousEvidenceSHA256:    state.active.record.EvidenceSHA256,
		PreviousPlanSHA256:        state.active.record.PlanSHA256,
		PreviousWithdrawn:         state.active.record.Withdrawn,
		Withdrawn:                 true,
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
		Sequence:       state.plan.Sequence,
		BundleSHA256:   state.active.record.BundleSHA256,
		EnvelopeSHA256: state.active.record.EnvelopeSHA256,
		EvidenceSHA256: hex.EncodeToString(evidenceDigest[:]),
		PlanSHA256:     state.currentPlan.PlanSHA256,
		Withdrawn:      true,
	}
	activeData, err := json.Marshal(active)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	return evidenceData, active, activeData, nil
}

func reproduceWithdrawnTrustStoreGeneration(ctx context.Context, generations *os.File, bundleData, envelopeData []byte, active TrustStoreActiveRecord, evidence TrustStoreGenerationEvidence, suppliedPolicy TrustMetadataPolicy, publicationTime, evaluationTime time.Time, depth int) (TrustBundlePlan, error) {
	if !active.Withdrawn || !evidence.Withdrawn || evidence.Purpose != trustStoreWithdrawalGenerationPurpose {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal generation is not marked withdrawn")
	}
	operationData, currentPolicyData, nextPolicyData, currentPolicy, nextPolicy, err := decodeTrustStoreUpdateEvidence(evidence)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if evidence.PolicyRotated || !bytes.Equal(currentPolicyData, nextPolicyData) {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal cannot rotate the authorization policy")
	}
	suppliedPolicyData, err := canonicalTrustMetadataPolicyBytes(suppliedPolicy)
	if err != nil {
		return TrustBundlePlan{}, fmt.Errorf("validate supplied FFU trust-store policy: %w", err)
	}
	if !bytes.Equal(suppliedPolicyData, nextPolicyData) {
		return TrustBundlePlan{}, errors.New("supplied FFU trust-store policy does not match the signed withdrawal generation policy")
	}
	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	previous := TrustStoreActiveRecord{
		Schema:         trustStoreSchema,
		Purpose:        trustStoreActivePurpose,
		Generation:     evidence.PreviousGeneration,
		Sequence:       evidence.PreviousSequence,
		BundleSHA256:   evidence.PreviousBundleSHA256,
		EnvelopeSHA256: evidence.PreviousEnvelopeSHA256,
		EvidenceSHA256: evidence.PreviousEvidenceSHA256,
		PlanSHA256:     evidence.PreviousPlanSHA256,
		Withdrawn:      evidence.PreviousWithdrawn,
	}
	if err := validateTrustStoreActiveRecord(previous); err != nil {
		return TrustBundlePlan{}, fmt.Errorf("validate previous signed FFU trust withdrawal generation: %w", err)
	}
	if previous.Withdrawn || previous.Sequence >= active.Sequence {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal history does not move strictly backwards from an active bundle")
	}
	if active.BundleSHA256 != previous.BundleSHA256 || active.EnvelopeSHA256 != previous.EnvelopeSHA256 || evidence.BundleSHA256 != previous.BundleSHA256 || evidence.EnvelopeSHA256 != previous.EnvelopeSHA256 || evidence.PlanSHA256 != previous.PlanSHA256 || active.PlanSHA256 != previous.PlanSHA256 {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal tombstone does not preserve historical active evidence")
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	if hex.EncodeToString(bundleDigest[:]) != previous.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != previous.EnvelopeSHA256 {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal tombstone bytes do not match historical active evidence")
	}
	previousPublicationTime, err := trustStoreGenerationPublicationTime(generations, previous)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	previousPlan, err := loadTrustStoreGenerationDepth(ctx, generations, previous, currentPolicy, previousPublicationTime, depth+1)
	if err != nil {
		return TrustBundlePlan{}, fmt.Errorf("reproduce previous signed FFU trust withdrawal generation: %w", err)
	}
	verifiedOperation, err := verifyTrustUpdateOperation(operationData, previous, previousPlan, previousPublicationTime, currentVerified, nextVerified, nil, nil, publicationTime)
	if err != nil {
		return TrustBundlePlan{}, fmt.Errorf("reproduce signed FFU trust withdrawal authorization: %w", err)
	}
	if verifiedOperation.document.Action != trustUpdateActionWithdraw || verifiedOperation.rotated {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal generation was not authorized by an unchanged-policy withdrawal operation")
	}
	updatePlan := buildTrustBundleUpdatePlan(previous, previousPlan, previousPublicationTime, verifiedOperation, currentVerified, nextVerified, nil, operationData, publicationTime)
	if updatePlan.PlanSHA256 != evidence.UpdatePlanSHA256 {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal authorization plan does not match durable evidence")
	}
	if updatePlan.PolicyRotated != evidence.PolicyRotated || !equalTrustStoreStrings(updatePlan.OperationSigningKeyIDs, evidence.OperationSigningKeyIDs) || len(evidence.ReplacementSigningKeyIDs) != 0 {
		return TrustBundlePlan{}, errors.New("signed FFU trust withdrawal authorization evidence does not match durable signer evidence")
	}
	if err := verifyTrustStoreAuthenticationEvidence(previousPlan, evidence); err != nil {
		return TrustBundlePlan{}, err
	}
	_ = evaluationTime // A withdrawn bundle is replayed historically, never reactivated at the caller's time.
	return previousPlan, nil
}
