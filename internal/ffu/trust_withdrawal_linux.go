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

// ErrTrustBundleWithdrawn identifies a fully verified durable withdrawal
// tombstone. Callers must not treat this state as an absent or active bundle.
var ErrTrustBundleWithdrawn = errors.New("ffu trust bundle is withdrawn")

// TrustBundleWithdrawal is the restart-verifiable result of one signed
// withdrawal. Historical bundle and distrust evidence remain immutable, while
// no trust anchor is active.
type TrustBundleWithdrawal struct {
	Root                      string                 `json:"root"`
	Generation                string                 `json:"generation"`
	PreviousGeneration        string                 `json:"previous_generation"`
	Active                    TrustStoreActiveRecord `json:"active"`
	AuthorizationPlan         TrustBundleUpdatePlan  `json:"authorization_plan"`
	PreservedDistrustedSHA256 []string               `json:"preserved_distrusted_sha256"`
	PublicationPerformed      bool                   `json:"publication_performed"`
	WithdrawalPerformed       bool                   `json:"withdrawal_performed"`
	TrustAnchorsActivated     bool                   `json:"trust_anchors_activated"`
	HostTLSStoreConsulted     bool                   `json:"host_tls_store_consulted"`
	CertificateChainBuilt     bool                   `json:"certificate_chain_built"`
	PublisherTrusted          bool                   `json:"publisher_trusted"`
}

// TrustBundleWithdrawnError carries the verified tombstone evidence while
// preserving errors.Is(err, ErrTrustBundleWithdrawn).
type TrustBundleWithdrawnError struct {
	Withdrawal TrustBundleWithdrawal
}

func (err *TrustBundleWithdrawnError) Error() string {
	if err == nil {
		return ErrTrustBundleWithdrawn.Error()
	}
	return fmt.Sprintf("%s at generation %s", ErrTrustBundleWithdrawn, err.Withdrawal.Generation)
}

func (err *TrustBundleWithdrawnError) Unwrap() error { return ErrTrustBundleWithdrawn }

// ApplyAuthenticatedTrustBundleWithdrawalOperation executes one signed
// withdrawal while holding the trust-store root lock. It commits a sealed
// tombstone generation and atomically exchanges active.json; it never deletes
// historical state or activates roots.
func ApplyAuthenticatedTrustBundleWithdrawalOperation(
	ctx context.Context,
	root string,
	operationData []byte,
	currentPolicy TrustMetadataPolicy,
	nextPolicy TrustMetadataPolicy,
	evaluationTime time.Time,
	opts TrustUpdateApplyOptions,
) (result TrustBundleWithdrawal, returnErr error) {
	if ctx == nil {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if evaluationTime.IsZero() {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal evaluation time is zero")
	}
	if len(operationData) == 0 || len(operationData) > maxTrustUpdateBytes {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal operation size is invalid")
	}
	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return TrustBundleWithdrawal{}, fmt.Errorf("current FFU trust withdrawal policy: %w", err)
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return TrustBundleWithdrawal{}, fmt.Errorf("replacement FFU trust withdrawal policy: %w", err)
	}
	currentPolicyData, err := canonicalTrustMetadataPolicyBytes(currentPolicy)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	nextPolicyData, err := canonicalTrustMetadataPolicyBytes(nextPolicy)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if !bytes.Equal(currentPolicyData, nextPolicyData) {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal cannot rotate the authorization policy")
	}

	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	defer rootFile.Close()
	generations, err := openTrustStoreDirectory(rootFile, trustStoreGenerationsName)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}

	state, err := planAuthenticatedTrustBundleOperationOpen(
		ctx, resolved, rootFile, rootIdentity, generations, generationsIdentity,
		operationData, currentPolicy, nextPolicy, currentVerified, nextVerified,
		nil, nil, evaluationTime,
	)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if state.plan.Action != trustUpdateActionWithdraw || state.candidatePlan != nil {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal accepts withdrawal operations only")
	}
	if state.plan.PolicyRotated || !state.plan.CurrentStateValidated || !state.plan.OperationAuthenticated || state.plan.CandidateAuthenticated || state.plan.PublicationPerformed || state.plan.WithdrawalPerformed || state.plan.TrustAnchorsActivated || state.plan.CertificateChainBuilt || state.plan.PublisherTrusted {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal received an invalid authorization plan")
	}
	if err := trustUpdateApplyStage(ctx, opts, "authorized"); err != nil {
		return TrustBundleWithdrawal{}, err
	}

	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, state.active); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	bundleData, envelopeData, err := readTrustStorePayloadForWithdrawal(ctx, generations, state.active.record)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}

	generation := trustStoreGenerationName(state.plan.Sequence, state.active.record.BundleSHA256, state.active.record.EnvelopeSHA256)
	evidenceData, active, activeData, err := buildTrustStoreWithdrawalRecords(
		generation, bundleData, envelopeData, operationData, currentPolicyData, nextPolicyData, state,
	)
	if err != nil {
		return TrustBundleWithdrawal{}, err
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
		withdrawal, loadErr := loadVerifiedTrustStoreWithdrawal(ctx, generations, active, currentPolicy, evaluationTime)
		if loadErr != nil {
			return TrustBundleWithdrawal{}, fmt.Errorf("existing signed FFU trust withdrawal generation is invalid: %w", loadErr)
		}
		if withdrawal.AuthorizationPlan.PlanSHA256 != state.plan.PlanSHA256 {
			return TrustBundleWithdrawal{}, errors.New("existing signed FFU trust withdrawal generation has different authorization evidence")
		}
	case errors.Is(err, os.ErrNotExist):
		tempName, tempDirectory, createErr := createTrustStoreGenerationTemporary(generations)
		if createErr != nil {
			return TrustBundleWithdrawal{}, createErr
		}
		transaction.generationTemp = tempName
		if err := trustUpdateApplyStage(ctx, opts, "generation-created"); err != nil {
			tempDirectory.Close()
			return TrustBundleWithdrawal{}, err
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
			return TrustBundleWithdrawal{}, errors.Join(writeErr, closeErr)
		}
		if err := trustUpdateApplyStage(ctx, opts, "generation-synced"); err != nil {
			return TrustBundleWithdrawal{}, err
		}
		if err := trustStoreRenameNoReplace(generations, tempName, generation); err != nil {
			return TrustBundleWithdrawal{}, fmt.Errorf("publish signed FFU trust withdrawal generation: %w", err)
		}
		transaction.generationTemp = ""
		transaction.generationAdded = true
		if err := syncTrustStoreDirectory(generations); err != nil {
			return TrustBundleWithdrawal{}, err
		}
		if err := trustUpdateApplyStage(ctx, opts, "generation-published"); err != nil {
			return TrustBundleWithdrawal{}, err
		}
	default:
		return TrustBundleWithdrawal{}, err
	}

	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, state.active); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	activeTemp, err := writeTrustStoreTemporary(rootFile, trustStoreTempActive, activeData, 0o600)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	transaction.activeTemp = activeTemp
	if err := trustUpdateApplyStage(ctx, opts, "active-staged"); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := trustStoreRenameExchange(rootFile, activeTemp, trustStoreActiveName); err != nil {
		return TrustBundleWithdrawal{}, fmt.Errorf("exchange signed FFU trust withdrawal active record: %w", err)
	}
	transaction.activeCommitted = true
	oldData, oldIdentity, err := readTrustStoreRegular(rootFile, activeTemp, maxTrustStoreActiveBytes, 0o600)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if !sameTrustStoreContentObject(oldIdentity, state.active.identity) || !bytes.Equal(oldData, state.active.data) {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal active record changed before atomic exchange")
	}
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := trustUpdateApplyStage(ctx, opts, "active-committed"); err != nil {
		return TrustBundleWithdrawal{}, err
	}

	withdrawal, err := loadVerifiedTrustStoreWithdrawal(ctx, generations, active, currentPolicy, evaluationTime)
	if err != nil {
		return TrustBundleWithdrawal{}, fmt.Errorf("verify committed signed FFU trust withdrawal generation: %w", err)
	}
	current, err := readTrustStoreActive(rootFile)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if !current.exists || current.record != active {
		return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal active record changed before verification")
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, current); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := trustUpdateApplyStage(ctx, opts, "verified"); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := removeTrustStoreExact(rootFile, transaction.activeTemp); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	transaction.activeTemp = ""
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	transaction.activeCommitted = false
	transaction.generationAdded = false
	withdrawal.Root = resolved
	return withdrawal, nil
}

// RecoverAuthenticatedTrustBundleWithdrawal verifies the active tombstone and
// returns its signed authorization evidence. Ordinary recovery and activation
// continue to fail with ErrTrustBundleWithdrawn.
func RecoverAuthenticatedTrustBundleWithdrawal(ctx context.Context, root string, policy TrustMetadataPolicy, evaluationTime time.Time, opts TrustStoreOptions) (TrustBundleWithdrawal, error) {
	if ctx == nil {
		return TrustBundleWithdrawal{}, errors.New("ffu trust withdrawal recovery context is nil")
	}
	if evaluationTime.IsZero() {
		return TrustBundleWithdrawal{}, errors.New("ffu trust withdrawal recovery evaluation time is zero")
	}
	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	defer rootFile.Close()
	generations, err := openTrustStoreDirectory(rootFile, trustStoreGenerationsName)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	active, err := readTrustStoreActive(rootFile)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if active.record.Purpose != trustStoreWithdrawnPurpose {
		return TrustBundleWithdrawal{}, errors.New("ffu trust-store active record is not a withdrawal tombstone")
	}
	withdrawal, err := loadVerifiedTrustStoreWithdrawal(ctx, generations, active.record, policy, evaluationTime)
	if err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := trustStoreStage(ctx, opts, "recovered"); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, active); err != nil {
		return TrustBundleWithdrawal{}, err
	}
	withdrawal.Root = resolved
	return withdrawal, nil
}

func loadVerifiedTrustStoreWithdrawal(ctx context.Context, generations *os.File, active TrustStoreActiveRecord, policy TrustMetadataPolicy, evaluationTime time.Time) (TrustBundleWithdrawal, error) {
	_, err := loadTrustStoreGeneration(ctx, generations, active, policy, evaluationTime)
	var withdrawn *TrustBundleWithdrawnError
	if !errors.As(err, &withdrawn) {
		if err == nil {
			return TrustBundleWithdrawal{}, errors.New("signed FFU trust withdrawal generation was accepted as an active bundle")
		}
		return TrustBundleWithdrawal{}, err
	}
	return withdrawn.Withdrawal, nil
}

func reproduceWithdrawnTrustStoreGeneration(ctx context.Context, generations *os.File, bundleData, envelopeData []byte, active TrustStoreActiveRecord, evidence TrustStoreGenerationEvidence, suppliedPolicy TrustMetadataPolicy, publicationTime time.Time, depth int) (*TrustBundleWithdrawal, error) {
	if active.Purpose != trustStoreWithdrawnPurpose || evidence.Purpose != trustStoreWithdrawalGenerationPurpose {
		return nil, errors.New("signed FFU trust withdrawal purpose is invalid")
	}
	operationData, currentPolicyData, nextPolicyData, currentPolicy, nextPolicy, err := decodeTrustStoreUpdateEvidence(evidence)
	if err != nil {
		return nil, err
	}
	suppliedPolicyData, err := canonicalTrustMetadataPolicyBytes(suppliedPolicy)
	if err != nil {
		return nil, fmt.Errorf("validate supplied FFU trust withdrawal policy: %w", err)
	}
	if !bytes.Equal(suppliedPolicyData, nextPolicyData) || !bytes.Equal(currentPolicyData, nextPolicyData) {
		return nil, errors.New("supplied FFU trust withdrawal policy does not match durable authorization evidence")
	}
	currentVerified, err := verifyTrustMetadataPolicy(currentPolicy)
	if err != nil {
		return nil, err
	}
	nextVerified, err := verifyTrustMetadataPolicy(nextPolicy)
	if err != nil {
		return nil, err
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
	}
	if err := validateTrustStoreActiveRecord(previous); err != nil {
		return nil, fmt.Errorf("validate previous signed FFU trust withdrawal generation: %w", err)
	}
	if previous.Sequence >= active.Sequence || active.BundleSHA256 != previous.BundleSHA256 || active.EnvelopeSHA256 != previous.EnvelopeSHA256 {
		return nil, errors.New("signed FFU trust withdrawal history or preserved payload binding is invalid")
	}
	previousPublicationTime, err := trustStoreGenerationPublicationTime(generations, previous)
	if err != nil {
		return nil, err
	}
	previousPlan, err := loadTrustStoreGenerationDepth(ctx, generations, previous, currentPolicy, previousPublicationTime, depth+1)
	if err != nil {
		return nil, fmt.Errorf("reproduce previous signed FFU trust withdrawal generation: %w", err)
	}
	verifiedOperation, err := verifyTrustUpdateOperation(operationData, previous, previousPlan, previousPublicationTime, currentVerified, nextVerified, nil, nil, publicationTime)
	if err != nil {
		return nil, fmt.Errorf("reproduce signed FFU trust withdrawal authorization: %w", err)
	}
	if verifiedOperation.document.Action != trustUpdateActionWithdraw || verifiedOperation.rotated {
		return nil, errors.New("signed FFU trust withdrawal evidence was not authorized by an unchanged-policy withdrawal")
	}
	updatePlan := buildTrustBundleUpdatePlan(previous, previousPlan, previousPublicationTime, verifiedOperation, currentVerified, nextVerified, nil, operationData, publicationTime)
	if updatePlan.PlanSHA256 != evidence.UpdatePlanSHA256 || updatePlan.PlanSHA256 != evidence.PlanSHA256 || updatePlan.PlanSHA256 != active.PlanSHA256 {
		return nil, errors.New("signed FFU trust withdrawal authorization plan does not match durable evidence")
	}
	if updatePlan.PolicyRotated || !equalTrustStoreStrings(updatePlan.OperationSigningKeyIDs, evidence.OperationSigningKeyIDs) || len(evidence.ReplacementSigningKeyIDs) != 0 {
		return nil, errors.New("signed FFU trust withdrawal signer evidence is invalid")
	}
	if err := verifyTrustStoreAuthenticationEvidence(previousPlan, evidence); err != nil {
		return nil, err
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	if hex.EncodeToString(bundleDigest[:]) != previous.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != previous.EnvelopeSHA256 {
		return nil, errors.New("signed FFU trust withdrawal did not preserve the previous immutable payload")
	}
	return &TrustBundleWithdrawal{
		Generation:                active.Generation,
		PreviousGeneration:        previous.Generation,
		Active:                    active,
		AuthorizationPlan:         updatePlan,
		PreservedDistrustedSHA256: append([]string(nil), previousPlan.DistrustedSHA256...),
		PublicationPerformed:      false,
		WithdrawalPerformed:       true,
		TrustAnchorsActivated:     false,
		HostTLSStoreConsulted:     false,
		CertificateChainBuilt:     false,
		PublisherTrusted:          false,
	}, nil
}

func buildTrustStoreWithdrawalRecords(generation string, bundleData, envelopeData, operationData, currentPolicyData, nextPolicyData []byte, state trustBundleUpdatePlanningState) ([]byte, TrustStoreActiveRecord, []byte, error) {
	if state.currentPlan.Authentication == nil || state.plan.Action != trustUpdateActionWithdraw || state.plan.PolicyRotated {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("signed FFU trust withdrawal lacks valid current authentication evidence")
	}
	envelopeDigest := sha256.Sum256(envelopeData)
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
		EnvelopeSHA256:            hex.EncodeToString(envelopeDigest[:]),
		SignedMetadataSHA256:      state.currentPlan.Authentication.MetadataSHA256,
		PlanSHA256:                state.plan.PlanSHA256,
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
	}
	evidenceData, err := json.Marshal(evidence)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	evidenceDigest := sha256.Sum256(evidenceData)
	active := TrustStoreActiveRecord{
		Schema:         trustStoreSchema,
		Purpose:        trustStoreWithdrawnPurpose,
		Generation:     generation,
		Sequence:       state.plan.Sequence,
		BundleSHA256:   state.active.record.BundleSHA256,
		EnvelopeSHA256: state.active.record.EnvelopeSHA256,
		EvidenceSHA256: hex.EncodeToString(evidenceDigest[:]),
		PlanSHA256:     state.plan.PlanSHA256,
	}
	activeData, err := json.Marshal(active)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	return evidenceData, active, activeData, nil
}

func readTrustStorePayloadForWithdrawal(ctx context.Context, generations *os.File, active TrustStoreActiveRecord) ([]byte, []byte, error) {
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
		return nil, nil, errors.New("signed FFU trust withdrawal requires a sealed 0500 generation")
	}
	if err := validateTrustStoreGenerationEntries(generation); err != nil {
		return nil, nil, err
	}
	bundleData, bundleIdentity, err := readTrustStoreRegular(generation, trustStoreBundleName, int(maxFFUTrustBundleBytes), 0o400)
	if err != nil {
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
	if err := trustStoreContext(ctx); err != nil {
		return nil, nil, err
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	evidenceDigest := sha256.Sum256(evidenceData)
	if hex.EncodeToString(bundleDigest[:]) != active.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != active.EnvelopeSHA256 || hex.EncodeToString(evidenceDigest[:]) != active.EvidenceSHA256 {
		return nil, nil, errors.New("signed FFU trust withdrawal payload does not match the current active record")
	}
	if err := verifyTrustStoreRegularSnapshot(generation, trustStoreBundleName, bundleIdentity, int(maxFFUTrustBundleBytes), 0o400); err != nil {
		return nil, nil, err
	}
	if err := verifyTrustStoreRegularSnapshot(generation, trustStoreEnvelopeName, envelopeIdentity, maxFFUTrustMetadataBytes, 0o400); err != nil {
		return nil, nil, err
	}
	if err := verifyTrustStoreRegularSnapshot(generation, trustStoreEvidenceName, evidenceIdentity, maxTrustStoreEvidenceBytes, 0o400); err != nil {
		return nil, nil, err
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(generations, active.Generation, generationIdentity); err != nil {
		return nil, nil, err
	}
	return bundleData, envelopeData, nil
}
