//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	trustStoreSchema            = 1
	trustStoreGenerationPurpose = "ffu-trust-bundle-generation"
	trustStoreActivePurpose     = "ffu-trust-bundle-active"
	trustStoreGenerationsName   = "generations"
	trustStoreActiveName        = "active.json"
	trustStoreBundleName        = "bundle.json"
	trustStoreEnvelopeName      = "metadata.json"
	trustStoreEvidenceName      = "evidence.json"
	trustStoreGenerationPrefix  = "generation-"
	trustStoreTempGeneration    = ".generation-"
	trustStoreTempActive        = ".active-"
	maxTrustStoreEvidenceBytes  = 128 << 10
	maxTrustStoreActiveBytes    = 32 << 10
	maxTrustStoreGenerations    = 256
)

// TrustStoreOptions configures durable publication. The hook is intentionally
// package-private and exists only for deterministic interruption tests.
type TrustStoreOptions struct {
	hook func(stage string) error
}

// TrustStoreActiveRecord is the single atomic commit point for a published,
// still-inactive trust-bundle generation.
type TrustStoreActiveRecord struct {
	Schema         int    `json:"schema"`
	Purpose        string `json:"purpose"`
	Generation     string `json:"generation"`
	Sequence       uint64 `json:"sequence"`
	BundleSHA256   string `json:"bundle_sha256"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	PlanSHA256     string `json:"plan_sha256"`
}

// TrustStoreGenerationEvidence binds the immutable files in one generation to
// the authenticated plan that justified publication.
type TrustStoreGenerationEvidence struct {
	Schema                    int      `json:"schema"`
	Purpose                   string   `json:"purpose"`
	Generation                string   `json:"generation"`
	Sequence                  uint64   `json:"sequence"`
	BundleSize                uint64   `json:"bundle_size"`
	BundleSHA256              string   `json:"bundle_sha256"`
	EnvelopeSize              uint64   `json:"envelope_size"`
	EnvelopeSHA256            string   `json:"envelope_sha256"`
	SignedMetadataSHA256      string   `json:"signed_metadata_sha256"`
	PlanSHA256                string   `json:"plan_sha256"`
	KeySetVersion             uint64   `json:"key_set_version"`
	KeySetSHA256              string   `json:"key_set_sha256"`
	Threshold                 int      `json:"threshold"`
	SigningKeyIDs             []string `json:"signing_key_ids"`
	PreviousSequence          uint64   `json:"previous_sequence"`
	PreviousBundleSHA256      string   `json:"previous_bundle_sha256,omitempty"`
	PublicationEvaluationTime string   `json:"publication_evaluation_time"`
	TrustAnchorsActivated     bool     `json:"trust_anchors_activated"`
}

// TrustStoreResult reports the exact committed generation. The plan remains
// inactive even after durable publication.
type TrustStoreResult struct {
	Root               string                 `json:"root"`
	Generation         string                 `json:"generation"`
	PreviousGeneration string                 `json:"previous_generation,omitempty"`
	Reused             bool                   `json:"reused"`
	Active             TrustStoreActiveRecord `json:"active"`
	Plan               TrustBundlePlan        `json:"plan"`
}

type trustStoreFileIdentity struct {
	device     uint64
	inode      uint64
	mode       uint32
	size       int64
	modifiedNS int64
	changedNS  int64
	uid        uint32
	nlink      uint64
}

type trustStoreActiveSnapshot struct {
	exists   bool
	data     []byte
	identity trustStoreFileIdentity
	record   TrustStoreActiveRecord
}

type trustStoreTransaction struct {
	root             *os.File
	generations      *os.File
	generationTemp   string
	generationFinal  string
	generationAdded  bool
	activeTemp       string
	activeCommitted  bool
	activeWasPresent bool
	activeNew        TrustStoreActiveRecord
	previous         trustStoreActiveSnapshot
}

// PublishAuthenticatedTrustBundle durably stores an already authenticated,
// still-inactive bundle. Immutable generation files are published first; one
// atomic active-record update is the commit point.
func PublishAuthenticatedTrustBundle(ctx context.Context, root string, bundleData, envelopeData []byte, policy TrustMetadataPolicy, evaluationTime time.Time, opts TrustStoreOptions) (result TrustStoreResult, returnErr error) {
	if ctx == nil {
		return TrustStoreResult{}, errors.New("FFU trust-store context is nil")
	}
	if err := ctx.Err(); err != nil {
		return TrustStoreResult{}, context.Cause(ctx)
	}
	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustStoreResult{}, err
	}
	defer rootFile.Close()
	generations, err := openOrCreateTrustStoreGenerations(rootFile)
	if err != nil {
		return TrustStoreResult{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustStoreResult{}, err
	}
	transaction := &trustStoreTransaction{root: rootFile, generations: generations}
	defer func() {
		if returnErr == nil {
			return
		}
		if rollbackErr := rollbackTrustStoreTransaction(transaction); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback FFU trust-store publication: %w", rollbackErr))
		}
	}()

	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustStoreResult{}, err
	}
	previous, _, err := readCurrentTrustStoreState(ctx, rootFile, generations, policy, evaluationTime)
	if err != nil {
		return TrustStoreResult{}, err
	}
	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustStoreResult{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustStoreResult{}, err
	}
	transaction.previous = previous
	transaction.activeWasPresent = previous.exists
	rollbackState := TrustMetadataRollbackState{}
	previousGeneration := ""
	if previous.exists {
		rollbackState = TrustMetadataRollbackState{Sequence: previous.record.Sequence, BundleSHA256: previous.record.BundleSHA256}
		previousGeneration = previous.record.Generation
	}

	plan, err := AuthenticateTrustBundleMetadata(bundleData, envelopeData, policy, rollbackState, evaluationTime)
	if err != nil {
		return TrustStoreResult{}, err
	}
	if err := requireInactiveAuthenticatedTrustPlan(plan); err != nil {
		return TrustStoreResult{}, err
	}
	envelopeDigest := sha256.Sum256(envelopeData)
	generation := trustStoreGenerationName(plan.Sequence, plan.BundleSHA256, hex.EncodeToString(envelopeDigest[:]))
	evidenceData, active, activeData, err := buildTrustStoreRecords(generation, bundleData, envelopeData, rollbackState, plan)
	if err != nil {
		return TrustStoreResult{}, err
	}
	transaction.generationFinal = generation
	transaction.activeNew = active
	if err := trustStoreStage(ctx, opts, "validated"); err != nil {
		return TrustStoreResult{}, err
	}

	if previous.exists && previous.record.Sequence == active.Sequence && previous.record.BundleSHA256 == active.BundleSHA256 && previous.record.EnvelopeSHA256 == active.EnvelopeSHA256 {
		loaded, err := loadTrustStoreGeneration(ctx, generations, previous.record, policy, evaluationTime)
		if err != nil {
			return TrustStoreResult{}, err
		}
		if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
			return TrustStoreResult{}, err
		}
		if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
			return TrustStoreResult{}, err
		}
		return TrustStoreResult{Root: resolved, Generation: previous.record.Generation, PreviousGeneration: previousGeneration, Reused: true, Active: previous.record, Plan: loaded}, nil
	}

	existing, err := trustStoreExactEntry(generations, generation)
	switch {
	case err == nil:
		_ = existing
		loaded, loadErr := loadTrustStoreGeneration(ctx, generations, active, policy, evaluationTime)
		if loadErr != nil {
			return TrustStoreResult{}, fmt.Errorf("existing FFU trust-store generation does not match authenticated input: %w", loadErr)
		}
		if loaded.PlanSHA256 != plan.PlanSHA256 {
			return TrustStoreResult{}, errors.New("existing FFU trust-store generation has a different authenticated plan")
		}
	case errors.Is(err, os.ErrNotExist):
		tempName, tempDirectory, createErr := createTrustStoreGenerationTemporary(generations)
		if createErr != nil {
			return TrustStoreResult{}, createErr
		}
		transaction.generationTemp = tempName
		if err := trustStoreStage(ctx, opts, "generation-created"); err != nil {
			tempDirectory.Close()
			return TrustStoreResult{}, err
		}
		writeErr := writeTrustStoreFile(tempDirectory, trustStoreBundleName, bundleData, 0o400)
		if writeErr == nil {
			writeErr = trustStoreStage(ctx, opts, "bundle-staged")
		}
		if writeErr == nil {
			writeErr = writeTrustStoreFile(tempDirectory, trustStoreEnvelopeName, envelopeData, 0o400)
		}
		if writeErr == nil {
			writeErr = trustStoreStage(ctx, opts, "metadata-staged")
		}
		if writeErr == nil {
			writeErr = writeTrustStoreFile(tempDirectory, trustStoreEvidenceName, evidenceData, 0o400)
		}
		if writeErr == nil {
			writeErr = trustStoreStage(ctx, opts, "evidence-staged")
		}
		if writeErr == nil {
			writeErr = tempDirectory.Chmod(0o500)
		}
		if writeErr == nil {
			writeErr = syncTrustStoreDirectory(tempDirectory)
		}
		closeErr := tempDirectory.Close()
		if writeErr != nil || closeErr != nil {
			return TrustStoreResult{}, errors.Join(writeErr, closeErr)
		}
		if err := trustStoreStage(ctx, opts, "generation-synced"); err != nil {
			return TrustStoreResult{}, err
		}
		if err := trustStoreRenameNoReplace(generations, tempName, generation); err != nil {
			return TrustStoreResult{}, fmt.Errorf("publish FFU trust-store generation: %w", err)
		}
		transaction.generationTemp = ""
		transaction.generationAdded = true
		if err := syncTrustStoreDirectory(generations); err != nil {
			return TrustStoreResult{}, err
		}
		if err := trustStoreStage(ctx, opts, "generation-published"); err != nil {
			return TrustStoreResult{}, err
		}
	default:
		return TrustStoreResult{}, err
	}

	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustStoreResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, previous); err != nil {
		return TrustStoreResult{}, err
	}
	activeTemp, err := writeTrustStoreTemporary(rootFile, trustStoreTempActive, activeData, 0o600)
	if err != nil {
		return TrustStoreResult{}, fmt.Errorf("stage FFU trust-store active record: %w", err)
	}
	transaction.activeTemp = activeTemp
	if err := trustStoreStage(ctx, opts, "active-staged"); err != nil {
		return TrustStoreResult{}, err
	}
	if previous.exists {
		if err := trustStoreRenameExchange(rootFile, activeTemp, trustStoreActiveName); err != nil {
			return TrustStoreResult{}, fmt.Errorf("exchange FFU trust-store active record: %w", err)
		}
		transaction.activeCommitted = true
		oldData, oldIdentity, err := readTrustStoreRegular(rootFile, activeTemp, maxTrustStoreActiveBytes, 0o600)
		if err != nil {
			return TrustStoreResult{}, fmt.Errorf("inspect replaced FFU trust-store active record: %w", err)
		}
		if !sameTrustStoreContentObject(oldIdentity, previous.identity) || !bytes.Equal(oldData, previous.data) {
			return TrustStoreResult{}, errors.New("FFU trust-store active record changed before atomic exchange")
		}
	} else {
		if err := trustStoreRenameNoReplace(rootFile, activeTemp, trustStoreActiveName); err != nil {
			return TrustStoreResult{}, fmt.Errorf("publish FFU trust-store active record: %w", err)
		}
		transaction.activeTemp = ""
		transaction.activeCommitted = true
	}
	if err := syncTrustStoreDirectory(rootFile); err != nil {
		return TrustStoreResult{}, err
	}
	if err := trustStoreStage(ctx, opts, "active-committed"); err != nil {
		return TrustStoreResult{}, err
	}
	loaded, err := loadTrustStoreGeneration(ctx, generations, active, policy, evaluationTime)
	if err != nil {
		return TrustStoreResult{}, fmt.Errorf("verify committed FFU trust-store generation: %w", err)
	}
	current, err := readTrustStoreActive(rootFile)
	if err != nil {
		return TrustStoreResult{}, err
	}
	if !current.exists || current.record != active {
		return TrustStoreResult{}, errors.New("committed FFU trust-store active record changed before verification")
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustStoreResult{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustStoreResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, current); err != nil {
		return TrustStoreResult{}, err
	}
	if err := trustStoreStage(ctx, opts, "verified"); err != nil {
		return TrustStoreResult{}, err
	}
	if transaction.activeTemp != "" {
		if err := removeTrustStoreExact(rootFile, transaction.activeTemp); err != nil {
			return TrustStoreResult{}, fmt.Errorf("remove previous FFU trust-store active record: %w", err)
		}
		transaction.activeTemp = ""
		if err := syncTrustStoreDirectory(rootFile); err != nil {
			return TrustStoreResult{}, err
		}
	}
	transaction.activeCommitted = false
	transaction.generationAdded = false
	return TrustStoreResult{Root: resolved, Generation: generation, PreviousGeneration: previousGeneration, Active: active, Plan: loaded}, nil
}

// RecoverAuthenticatedTrustBundle validates the active generation and removes
// only known private temporary entries left by an interrupted transaction.
func RecoverAuthenticatedTrustBundle(ctx context.Context, root string, policy TrustMetadataPolicy, evaluationTime time.Time, opts TrustStoreOptions) (TrustStoreResult, error) {
	if ctx == nil {
		return TrustStoreResult{}, errors.New("FFU trust-store context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustStoreResult{}, err
	}
	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustStoreResult{}, err
	}
	defer rootFile.Close()
	generations, err := openOrCreateTrustStoreGenerations(rootFile)
	if err != nil {
		return TrustStoreResult{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustStoreResult{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustStoreResult{}, err
	}
	active, plan, err := readCurrentTrustStoreState(ctx, rootFile, generations, policy, evaluationTime)
	if err != nil {
		return TrustStoreResult{}, err
	}
	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustStoreResult{}, err
	}
	if !active.exists {
		return TrustStoreResult{}, os.ErrNotExist
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustStoreResult{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustStoreResult{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, active); err != nil {
		return TrustStoreResult{}, err
	}
	if err := trustStoreStage(ctx, opts, "recovered"); err != nil {
		return TrustStoreResult{}, err
	}
	return TrustStoreResult{Root: resolved, Generation: active.record.Generation, Active: active.record, Plan: plan, Reused: true}, nil
}

func buildTrustStoreRecords(generation string, bundleData, envelopeData []byte, previous TrustMetadataRollbackState, plan TrustBundlePlan) ([]byte, TrustStoreActiveRecord, []byte, error) {
	if plan.Authentication == nil {
		return nil, TrustStoreActiveRecord{}, nil, errors.New("authenticated FFU trust plan has no metadata evidence")
	}
	envelopeDigest := sha256.Sum256(envelopeData)
	evidence := TrustStoreGenerationEvidence{
		Schema:                    trustStoreSchema,
		Purpose:                   trustStoreGenerationPurpose,
		Generation:                generation,
		Sequence:                  plan.Sequence,
		BundleSize:                uint64(len(bundleData)),
		BundleSHA256:              plan.BundleSHA256,
		EnvelopeSize:              uint64(len(envelopeData)),
		EnvelopeSHA256:            hex.EncodeToString(envelopeDigest[:]),
		SignedMetadataSHA256:      plan.Authentication.MetadataSHA256,
		PlanSHA256:                plan.PlanSHA256,
		KeySetVersion:             plan.Authentication.KeySetVersion,
		KeySetSHA256:              plan.Authentication.KeySetSHA256,
		Threshold:                 plan.Authentication.Threshold,
		SigningKeyIDs:             append([]string(nil), plan.Authentication.SigningKeyIDs...),
		PreviousSequence:          previous.Sequence,
		PreviousBundleSHA256:      previous.BundleSHA256,
		PublicationEvaluationTime: plan.Authentication.EvaluationTime,
		TrustAnchorsActivated:     false,
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
		Sequence:       plan.Sequence,
		BundleSHA256:   plan.BundleSHA256,
		EnvelopeSHA256: evidence.EnvelopeSHA256,
		EvidenceSHA256: hex.EncodeToString(evidenceDigest[:]),
		PlanSHA256:     plan.PlanSHA256,
	}
	activeData, err := json.Marshal(active)
	if err != nil {
		return nil, TrustStoreActiveRecord{}, nil, err
	}
	return evidenceData, active, activeData, nil
}

func readCurrentTrustStoreState(ctx context.Context, root, generations *os.File, policy TrustMetadataPolicy, evaluationTime time.Time) (trustStoreActiveSnapshot, TrustBundlePlan, error) {
	active, err := readTrustStoreActive(root)
	if errors.Is(err, os.ErrNotExist) {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, nil
	}
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, err
	}
	plan, err := loadTrustStoreGeneration(ctx, generations, active.record, policy, evaluationTime)
	if err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, fmt.Errorf("validate current FFU trust-store generation: %w", err)
	}
	if err := verifyTrustStoreActiveSnapshot(root, active); err != nil {
		return trustStoreActiveSnapshot{}, TrustBundlePlan{}, err
	}
	return active, plan, nil
}

func loadTrustStoreGeneration(ctx context.Context, generations *os.File, active TrustStoreActiveRecord, policy TrustMetadataPolicy, evaluationTime time.Time) (TrustBundlePlan, error) {
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundlePlan{}, err
	}
	if err := validateTrustStoreActiveRecord(active); err != nil {
		return TrustBundlePlan{}, err
	}
	generation, err := openTrustStoreDirectory(generations, active.Generation)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	defer generation.Close()
	generationIdentity, err := trustStoreIdentityFromOpenFile(generation)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if os.FileMode(generationIdentity.mode).Perm() != 0o500 {
		return TrustBundlePlan{}, errors.New("FFU trust-store published generation mode must be 0500")
	}
	if err := validateTrustStoreGenerationEntries(generation); err != nil {
		return TrustBundlePlan{}, err
	}
	bundleData, bundleIdentity, err := readTrustStoreRegular(generation, trustStoreBundleName, int(maxFFUTrustBundleBytes), 0o400)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundlePlan{}, err
	}
	envelopeData, envelopeIdentity, err := readTrustStoreRegular(generation, trustStoreEnvelopeName, maxFFUTrustMetadataBytes, 0o400)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundlePlan{}, err
	}
	evidenceData, evidenceIdentity, err := readTrustStoreRegular(generation, trustStoreEvidenceName, maxTrustStoreEvidenceBytes, 0o400)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	bundleDigest := sha256.Sum256(bundleData)
	envelopeDigest := sha256.Sum256(envelopeData)
	evidenceDigest := sha256.Sum256(evidenceData)
	if hex.EncodeToString(bundleDigest[:]) != active.BundleSHA256 || hex.EncodeToString(envelopeDigest[:]) != active.EnvelopeSHA256 || hex.EncodeToString(evidenceDigest[:]) != active.EvidenceSHA256 {
		return TrustBundlePlan{}, errors.New("FFU trust-store active record does not match generation file digests")
	}
	evidence, err := parseTrustStoreEvidence(evidenceData)
	if err != nil {
		return TrustBundlePlan{}, err
	}
	if evidence.Generation != active.Generation || evidence.Sequence != active.Sequence || evidence.BundleSHA256 != active.BundleSHA256 || evidence.EnvelopeSHA256 != active.EnvelopeSHA256 || evidence.PlanSHA256 != active.PlanSHA256 {
		return TrustBundlePlan{}, errors.New("FFU trust-store evidence does not match the active record")
	}
	if evidence.BundleSize != uint64(len(bundleData)) || evidence.EnvelopeSize != uint64(len(envelopeData)) {
		return TrustBundlePlan{}, errors.New("FFU trust-store evidence does not match generation file sizes")
	}
	publicationTime, err := parseCanonicalTrustMetadataTime(evidence.PublicationEvaluationTime, "publication_evaluation_time")
	if err != nil {
		return TrustBundlePlan{}, err
	}
	publicationRollback := TrustMetadataRollbackState{Sequence: evidence.PreviousSequence, BundleSHA256: evidence.PreviousBundleSHA256}
	publicationPlan, err := AuthenticateTrustBundleMetadata(bundleData, envelopeData, policy, publicationRollback, publicationTime)
	if err != nil {
		return TrustBundlePlan{}, fmt.Errorf("reproduce FFU trust-store publication evidence: %w", err)
	}
	if err := requireInactiveAuthenticatedTrustPlan(publicationPlan); err != nil {
		return TrustBundlePlan{}, err
	}
	if publicationPlan.PlanSHA256 != active.PlanSHA256 || publicationPlan.PlanSHA256 != evidence.PlanSHA256 {
		return TrustBundlePlan{}, errors.New("FFU trust-store publication plan does not match durable evidence")
	}
	plan := publicationPlan
	if !evaluationTime.UTC().Equal(publicationTime) {
		plan, err = AuthenticateTrustBundleMetadata(bundleData, envelopeData, policy, TrustMetadataRollbackState{Sequence: active.Sequence, BundleSHA256: active.BundleSHA256}, evaluationTime)
		if err != nil {
			return TrustBundlePlan{}, err
		}
		if err := requireInactiveAuthenticatedTrustPlan(plan); err != nil {
			return TrustBundlePlan{}, err
		}
	}
	if plan.Authentication == nil || plan.Authentication.MetadataSHA256 != evidence.SignedMetadataSHA256 || plan.Authentication.KeySetVersion != evidence.KeySetVersion || plan.Authentication.KeySetSHA256 != evidence.KeySetSHA256 || plan.Authentication.Threshold != evidence.Threshold || !equalTrustStoreStrings(plan.Authentication.SigningKeyIDs, evidence.SigningKeyIDs) {
		return TrustBundlePlan{}, errors.New("FFU trust-store evidence does not match regenerated authentication evidence")
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
			return TrustBundlePlan{}, err
		}
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(generations, active.Generation, generationIdentity); err != nil {
		return TrustBundlePlan{}, err
	}
	return plan, nil
}

func parseTrustStoreEvidence(data []byte) (TrustStoreGenerationEvidence, error) {
	var evidence TrustStoreGenerationEvidence
	canonical, err := decodeCanonicalTrustStoreJSON(data, &evidence, "FFU trust-store generation evidence")
	if err != nil {
		return TrustStoreGenerationEvidence{}, err
	}
	_ = canonical
	if evidence.Schema != trustStoreSchema || evidence.Purpose != trustStoreGenerationPurpose || !validTrustStoreGenerationName(evidence.Generation) || evidence.Sequence == 0 || evidence.BundleSize == 0 || evidence.EnvelopeSize == 0 || evidence.Threshold <= 0 || evidence.TrustAnchorsActivated {
		return TrustStoreGenerationEvidence{}, errors.New("FFU trust-store generation evidence has an invalid schema or inactive-trust contract")
	}
	if _, err := validateTrustMetadataRollbackState(TrustMetadataRollbackState{Sequence: evidence.PreviousSequence, BundleSHA256: evidence.PreviousBundleSHA256}); err != nil {
		return TrustStoreGenerationEvidence{}, fmt.Errorf("invalid FFU trust-store previous rollback evidence: %w", err)
	}
	if evidence.PreviousSequence > evidence.Sequence || (evidence.PreviousSequence == evidence.Sequence && evidence.PreviousSequence != 0 && evidence.PreviousBundleSHA256 != evidence.BundleSHA256) {
		return TrustStoreGenerationEvidence{}, errors.New("FFU trust-store previous rollback evidence is inconsistent with the generation")
	}
	if _, err := parseCanonicalTrustMetadataTime(evidence.PublicationEvaluationTime, "publication_evaluation_time"); err != nil {
		return TrustStoreGenerationEvidence{}, err
	}
	for _, pair := range []struct{ value, field string }{{evidence.BundleSHA256, "bundle_sha256"}, {evidence.EnvelopeSHA256, "envelope_sha256"}, {evidence.SignedMetadataSHA256, "signed_metadata_sha256"}, {evidence.PlanSHA256, "plan_sha256"}, {evidence.KeySetSHA256, "key_set_sha256"}} {
		if _, err := canonicalSHA256Fingerprint(pair.value, pair.field); err != nil {
			return TrustStoreGenerationEvidence{}, err
		}
	}
	if len(evidence.SigningKeyIDs) < evidence.Threshold || !sort.StringsAreSorted(evidence.SigningKeyIDs) {
		return TrustStoreGenerationEvidence{}, errors.New("FFU trust-store signing-key evidence is incomplete or unsorted")
	}
	previous := ""
	for _, keyID := range evidence.SigningKeyIDs {
		if !canonicalTrustMetadataKeyID(keyID) || keyID == previous {
			return TrustStoreGenerationEvidence{}, errors.New("FFU trust-store signing-key evidence contains an invalid or duplicate key id")
		}
		previous = keyID
	}
	return evidence, nil
}

func readTrustStoreActive(root *os.File) (trustStoreActiveSnapshot, error) {
	data, identity, err := readTrustStoreRegular(root, trustStoreActiveName, maxTrustStoreActiveBytes, 0o600)
	if err != nil {
		return trustStoreActiveSnapshot{}, err
	}
	var record TrustStoreActiveRecord
	if _, err := decodeCanonicalTrustStoreJSON(data, &record, "FFU trust-store active record"); err != nil {
		return trustStoreActiveSnapshot{}, err
	}
	if err := validateTrustStoreActiveRecord(record); err != nil {
		return trustStoreActiveSnapshot{}, err
	}
	return trustStoreActiveSnapshot{exists: true, data: data, identity: identity, record: record}, nil
}

func validateTrustStoreActiveRecord(record TrustStoreActiveRecord) error {
	if record.Schema != trustStoreSchema || record.Purpose != trustStoreActivePurpose || record.Sequence == 0 || !validTrustStoreGenerationName(record.Generation) {
		return errors.New("FFU trust-store active record has an invalid schema or generation")
	}
	for _, pair := range []struct{ value, field string }{{record.BundleSHA256, "bundle_sha256"}, {record.EnvelopeSHA256, "envelope_sha256"}, {record.EvidenceSHA256, "evidence_sha256"}, {record.PlanSHA256, "plan_sha256"}} {
		if _, err := canonicalSHA256Fingerprint(pair.value, pair.field); err != nil {
			return err
		}
	}
	expectedPrefix := fmt.Sprintf("%s%020d-%s-%s", trustStoreGenerationPrefix, record.Sequence, record.BundleSHA256, record.EnvelopeSHA256)
	if record.Generation != expectedPrefix {
		return errors.New("FFU trust-store active generation name does not match its sequence and digests")
	}
	return nil
}

func decodeCanonicalTrustStoreJSON(data []byte, destination any, label string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", label)
	}
	if err := rejectDuplicateTrustMetadataJSONMembers(data); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s contains multiple JSON values", label)
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%s is not canonical JSON", label)
	}
	return canonical, nil
}

func requireInactiveAuthenticatedTrustPlan(plan TrustBundlePlan) error {
	if !plan.BundleStructureValidated || !plan.BundleSignatureAuthenticated || plan.Authentication == nil {
		return errors.New("FFU trust-store publication requires an authenticated bundle plan")
	}
	if plan.TrustAnchorsActivated || plan.HostTLSStoreConsulted || plan.CertificateChainBuilt || plan.PublisherTrusted {
		return errors.New("FFU trust-store publication refuses a plan that crossed the inactive trust boundary")
	}
	return nil
}

func trustStoreGenerationName(sequence uint64, bundleSHA256, envelopeSHA256 string) string {
	return fmt.Sprintf("%s%020d-%s-%s", trustStoreGenerationPrefix, sequence, bundleSHA256, envelopeSHA256)
}

func validTrustStoreGenerationName(name string) bool {
	if !strings.HasPrefix(name, trustStoreGenerationPrefix) || len(name) != len(trustStoreGenerationPrefix)+20+1+64+1+64 {
		return false
	}
	sequenceText := name[len(trustStoreGenerationPrefix) : len(trustStoreGenerationPrefix)+20]
	for _, character := range sequenceText {
		if character < '0' || character > '9' {
			return false
		}
	}
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil || sequence == 0 {
		return false
	}
	parts := strings.Split(name[len(trustStoreGenerationPrefix)+21:], "-")
	if len(parts) != 2 {
		return false
	}
	for _, value := range parts {
		if len(value) != 64 || value != strings.ToLower(value) {
			return false
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return false
		}
	}
	return true
}

func trustStoreStage(ctx context.Context, opts TrustStoreOptions, stage string) error {
	if err := trustStoreContext(ctx); err != nil {
		return err
	}
	if opts.hook != nil {
		if err := opts.hook(stage); err != nil {
			return fmt.Errorf("injected FFU trust-store failure at %s: %w", stage, err)
		}
	}
	return trustStoreContext(ctx)
}

func trustStoreContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("FFU trust-store context is nil")
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	return nil
}

func openTrustStoreRoot(root string) (string, *os.File, trustStoreFileIdentity, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil, trustStoreFileIdentity{}, errors.New("FFU trust-store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, trustStoreFileIdentity{}, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, trustStoreFileIdentity{}, fmt.Errorf("resolve FFU trust-store root: %w", err)
	}
	if filepath.Clean(absolute) != filepath.Clean(resolved) {
		return "", nil, trustStoreFileIdentity{}, errors.New("FFU trust-store root path must not contain symbolic links")
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, trustStoreFileIdentity{}, err
	}
	identity, err := trustStoreIdentityFromInfo(info)
	if err != nil {
		return "", nil, trustStoreFileIdentity{}, err
	}
	if err := validateTrustStoreDirectoryIdentity(identity, "FFU trust-store root"); err != nil {
		return "", nil, trustStoreFileIdentity{}, err
	}
	if os.FileMode(identity.mode).Perm() != 0o700 {
		return "", nil, trustStoreFileIdentity{}, errors.New("FFU trust-store root mode must be 0700")
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, trustStoreFileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), resolved)
	if file == nil {
		_ = syscall.Close(fd)
		return "", nil, trustStoreFileIdentity{}, errors.New("create FFU trust-store root descriptor")
	}
	actual, err := trustStoreIdentityFromOpenFile(file)
	if err != nil || !sameTrustStoreKernelObject(identity, actual) {
		file.Close()
		if err != nil {
			return "", nil, trustStoreFileIdentity{}, err
		}
		return "", nil, trustStoreFileIdentity{}, errors.New("FFU trust-store root changed while it was opened")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return "", nil, trustStoreFileIdentity{}, fmt.Errorf("lock FFU trust-store root: %w", err)
	}
	return resolved, file, actual, nil
}

func openOrCreateTrustStoreGenerations(root *os.File) (*os.File, error) {
	entry, err := trustStoreExactEntry(root, trustStoreGenerationsName)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(trustStoreDescriptorPath(root, trustStoreGenerationsName), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create FFU trust-store generations directory: %w", err)
		}
		if err := syncTrustStoreDirectory(root); err != nil {
			return nil, err
		}
		entry, err = trustStoreExactEntry(root, trustStoreGenerationsName)
	}
	if err != nil {
		return nil, err
	}
	_ = entry
	directory, err := openTrustStoreDirectory(root, trustStoreGenerationsName)
	if err != nil {
		return nil, err
	}
	identity, err := trustStoreIdentityFromOpenFile(directory)
	if err != nil {
		directory.Close()
		return nil, err
	}
	if os.FileMode(identity.mode).Perm() != 0o700 {
		directory.Close()
		return nil, errors.New("FFU trust-store generations directory mode must be 0700")
	}
	return directory, nil
}

type trustStoreEntry struct {
	entry os.DirEntry
}

func trustStoreExactEntry(directory *os.File, expected string) (trustStoreEntry, error) {
	listing, err := reopenTrustStoreDirectory(directory)
	if err != nil {
		return trustStoreEntry{}, err
	}
	defer listing.Close()
	entries, err := listing.ReadDir(-1)
	if err != nil {
		return trustStoreEntry{}, err
	}
	var match os.DirEntry
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), expected) {
			continue
		}
		if match != nil {
			return trustStoreEntry{}, fmt.Errorf("directory contains multiple case-equivalent %q entries", expected)
		}
		if entry.Name() != expected {
			return trustStoreEntry{}, fmt.Errorf("directory entry %q must use exact spelling %q", entry.Name(), expected)
		}
		match = entry
	}
	if match == nil {
		return trustStoreEntry{}, os.ErrNotExist
	}
	return trustStoreEntry{entry: match}, nil
}

func openTrustStoreDirectory(parent *os.File, name string) (*os.File, error) {
	if _, err := trustStoreExactEntry(parent, name); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create FFU trust-store directory descriptor")
	}
	actual, err := trustStoreIdentityFromOpenFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := validateTrustStoreDirectoryIdentity(actual, "FFU trust-store directory"); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func reopenTrustStoreDirectory(directory *os.File) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), directory.Name())
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("reopen FFU trust-store directory descriptor")
	}
	expected, err := trustStoreIdentityFromOpenFile(directory)
	if err != nil {
		file.Close()
		return nil, err
	}
	actual, err := trustStoreIdentityFromOpenFile(file)
	if err != nil || !sameTrustStoreKernelObject(expected, actual) {
		file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("FFU trust-store directory changed while it was reopened")
	}
	return file, nil
}

func createTrustStoreGenerationTemporary(generations *os.File) (string, *os.File, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomTrustStoreName(trustStoreTempGeneration)
		if err != nil {
			return "", nil, err
		}
		if err := os.Mkdir(trustStoreDescriptorPath(generations, name), 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", nil, err
		}
		directory, err := openTrustStoreDirectory(generations, name)
		if err != nil {
			_ = os.Remove(trustStoreDescriptorPath(generations, name))
			return "", nil, err
		}
		return name, directory, nil
	}
	return "", nil, errors.New("could not allocate a private FFU trust-store generation name")
}

func writeTrustStoreFile(directory *os.File, name string, data []byte, mode uint32) error {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(directory.Name(), name))
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("create FFU trust-store file descriptor")
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Chmod(os.FileMode(mode))
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func writeTrustStoreTemporary(directory *os.File, prefix string, data []byte, mode uint32) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomTrustStoreName(prefix)
		if err != nil {
			return "", err
		}
		if err := writeTrustStoreFile(directory, name, data, mode); errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("could not allocate a private FFU trust-store active-record name")
}

func openTrustStoreRegularDescriptor(directory *os.File, name string, expectedPerm os.FileMode) (*os.File, error) {
	if _, err := trustStoreExactEntry(directory, name); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(directory.Name(), name))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create FFU trust-store file descriptor")
	}
	identity, err := trustStoreIdentityFromOpenFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := validateTrustStoreRegularIdentity(identity, expectedPerm, "FFU trust-store file"); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func readTrustStoreRegular(directory *os.File, name string, maximum int, expectedPerm os.FileMode) ([]byte, trustStoreFileIdentity, error) {
	file, err := openTrustStoreRegularDescriptor(directory, name, expectedPerm)
	if err != nil {
		return nil, trustStoreFileIdentity{}, err
	}
	defer file.Close()
	identity, err := trustStoreIdentityFromOpenFile(file)
	if err != nil {
		return nil, trustStoreFileIdentity{}, err
	}
	if identity.size <= 0 || identity.size > int64(maximum) {
		return nil, trustStoreFileIdentity{}, fmt.Errorf("FFU trust-store file size must be between 1 and %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, trustStoreFileIdentity{}, err
	}
	after, err := trustStoreIdentityFromOpenFile(file)
	if err != nil || !sameTrustStoreStableObject(identity, after) || len(data) != int(identity.size) {
		if err != nil {
			return nil, trustStoreFileIdentity{}, err
		}
		return nil, trustStoreFileIdentity{}, errors.New("FFU trust-store file changed while it was read")
	}
	return data, identity, nil
}

func validTrustStoreTemporaryName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+24 {
		return false
	}
	suffix := name[len(prefix):]
	if suffix != strings.ToLower(suffix) {
		return false
	}
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 12
}

func validateTrustStoreNames(root, generations *os.File) error {
	rootListing, err := reopenTrustStoreDirectory(root)
	if err != nil {
		return err
	}
	rootEntries, err := rootListing.ReadDir(-1)
	rootListing.Close()
	if err != nil {
		return err
	}
	if len(rootEntries) > 2+maxFFUTrustMetadataSignatures {
		return errors.New("FFU trust-store root contains too many entries")
	}
	for _, entry := range rootEntries {
		name := entry.Name()
		if name == trustStoreGenerationsName || name == trustStoreActiveName {
			continue
		}
		if !validTrustStoreTemporaryName(name, trustStoreTempActive) {
			return fmt.Errorf("unexpected FFU trust-store root entry %q", name)
		}
		file, err := openTrustStoreRegularDescriptor(root, name, 0o600)
		if err != nil {
			return fmt.Errorf("invalid FFU trust-store temporary active record %q: %w", name, err)
		}
		file.Close()
	}
	generationListing, err := reopenTrustStoreDirectory(generations)
	if err != nil {
		return err
	}
	entries, err := generationListing.ReadDir(-1)
	generationListing.Close()
	if err != nil {
		return err
	}
	if len(entries) > maxTrustStoreGenerations+maxFFUTrustMetadataSignatures {
		return errors.New("FFU trust-store contains too many generation entries")
	}
	finalCount := 0
	for _, entry := range entries {
		name := entry.Name()
		if validTrustStoreGenerationName(name) {
			finalCount++
			directory, err := openTrustStoreDirectory(generations, name)
			if err != nil {
				return fmt.Errorf("invalid FFU trust-store generation %q: %w", name, err)
			}
			identity, identityErr := trustStoreIdentityFromOpenFile(directory)
			directory.Close()
			if identityErr != nil {
				return identityErr
			}
			if os.FileMode(identity.mode).Perm() != 0o500 {
				return fmt.Errorf("FFU trust-store generation %q mode must be 0500", name)
			}
			continue
		}
		if !validTrustStoreTemporaryName(name, trustStoreTempGeneration) {
			return fmt.Errorf("unexpected FFU trust-store generation entry %q", name)
		}
		directory, err := openTrustStoreDirectory(generations, name)
		if err != nil {
			return fmt.Errorf("invalid FFU trust-store temporary generation %q: %w", name, err)
		}
		directory.Close()
	}
	if finalCount > maxTrustStoreGenerations {
		return fmt.Errorf("FFU trust-store generation count exceeds %d", maxTrustStoreGenerations)
	}
	return nil
}

func validateTrustStoreGenerationEntries(directory *os.File) error {
	listing, err := reopenTrustStoreDirectory(directory)
	if err != nil {
		return err
	}
	defer listing.Close()
	entries, err := listing.ReadDir(-1)
	if err != nil {
		return err
	}
	expected := map[string]bool{trustStoreBundleName: false, trustStoreEnvelopeName: false, trustStoreEvidenceName: false}
	for _, entry := range entries {
		seen, ok := expected[entry.Name()]
		if !ok {
			return fmt.Errorf("unexpected FFU trust-store generation file %q", entry.Name())
		}
		if seen {
			return fmt.Errorf("duplicate FFU trust-store generation file %q", entry.Name())
		}
		expected[entry.Name()] = true
	}
	for name, present := range expected {
		if !present {
			return fmt.Errorf("missing FFU trust-store generation file %q", name)
		}
	}
	return nil
}

func verifyTrustStoreActiveSnapshot(root *os.File, snapshot trustStoreActiveSnapshot) error {
	current, err := readTrustStoreActive(root)
	if !snapshot.exists {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("FFU trust-store active record appeared before commit")
	}
	if err != nil {
		return err
	}
	if !sameTrustStoreStableObject(snapshot.identity, current.identity) || !bytes.Equal(snapshot.data, current.data) {
		return errors.New("FFU trust-store active record changed before commit")
	}
	return nil
}

func cleanTrustStoreTemporaries(root, generations *os.File) error {
	var failures []error
	rootListing, err := reopenTrustStoreDirectory(root)
	if err != nil {
		return err
	}
	rootEntries, readErr := rootListing.ReadDir(-1)
	rootListing.Close()
	if readErr != nil {
		return readErr
	}
	for _, entry := range rootEntries {
		if strings.HasPrefix(entry.Name(), trustStoreTempActive) {
			if err := removeTrustStoreExact(root, entry.Name()); err != nil {
				failures = append(failures, err)
			}
		}
	}
	generationListing, err := reopenTrustStoreDirectory(generations)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	entries, readErr := generationListing.ReadDir(-1)
	generationListing.Close()
	if readErr != nil {
		return errors.Join(append(failures, readErr)...)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), trustStoreTempGeneration) {
			if err := removeTrustStoreGeneration(generations, entry.Name()); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := syncTrustStoreDirectory(root); err != nil {
		failures = append(failures, err)
	}
	if err := syncTrustStoreDirectory(generations); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func rollbackTrustStoreTransaction(transaction *trustStoreTransaction) error {
	if transaction == nil || transaction.root == nil || transaction.generations == nil {
		return nil
	}
	var failures []error
	if transaction.activeCommitted {
		if transaction.activeWasPresent && transaction.activeTemp != "" {
			if err := trustStoreRenameExchange(transaction.root, transaction.activeTemp, trustStoreActiveName); err != nil {
				failures = append(failures, err)
			} else {
				transaction.activeCommitted = false
			}
		} else if !transaction.activeWasPresent {
			current, err := readTrustStoreActive(transaction.root)
			if err == nil && current.record == transaction.activeNew {
				if err := removeTrustStoreExact(transaction.root, trustStoreActiveName); err != nil {
					failures = append(failures, err)
				}
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, err)
			}
		}
	}
	if transaction.activeTemp != "" {
		if err := removeTrustStoreExact(transaction.root, transaction.activeTemp); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if transaction.generationTemp != "" {
		if err := removeTrustStoreGeneration(transaction.generations, transaction.generationTemp); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if transaction.generationAdded {
		if err := removeTrustStoreGeneration(transaction.generations, transaction.generationFinal); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if err := syncTrustStoreDirectory(transaction.generations); err != nil {
		failures = append(failures, err)
	}
	if err := syncTrustStoreDirectory(transaction.root); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func removeTrustStoreGeneration(generations *os.File, name string) error {
	directory, err := openTrustStoreDirectory(generations, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := directory.Chmod(0o700); err != nil {
		directory.Close()
		return err
	}
	listing, err := reopenTrustStoreDirectory(directory)
	if err != nil {
		directory.Close()
		return err
	}
	entries, err := listing.ReadDir(-1)
	listing.Close()
	if err != nil {
		directory.Close()
		return err
	}
	for _, entry := range entries {
		if entry.Name() != trustStoreBundleName && entry.Name() != trustStoreEnvelopeName && entry.Name() != trustStoreEvidenceName {
			directory.Close()
			return fmt.Errorf("refuse to remove FFU trust-store generation with unexpected entry %q", entry.Name())
		}
		if err := removeTrustStoreExact(directory, entry.Name()); err != nil {
			directory.Close()
			return err
		}
	}
	if err := syncTrustStoreDirectory(directory); err != nil {
		directory.Close()
		return err
	}
	directory.Close()
	return os.Remove(trustStoreDescriptorPath(generations, name))
}

func removeTrustStoreExact(directory *os.File, name string) error {
	return os.Remove(trustStoreDescriptorPath(directory, name))
}

func verifyTrustStoreRegularSnapshot(directory *os.File, name string, expected trustStoreFileIdentity, maximum int, permissions os.FileMode) error {
	_, actual, err := readTrustStoreRegular(directory, name, maximum, permissions)
	if err != nil {
		return err
	}
	if !sameTrustStoreStableObject(expected, actual) {
		return fmt.Errorf("FFU trust-store file %q was replaced after verification", name)
	}
	return nil
}

func ensureTrustStoreDirectoryEntryIdentity(parent *os.File, name string, expected trustStoreFileIdentity) error {
	current, err := openTrustStoreDirectory(parent, name)
	if err != nil {
		return err
	}
	defer current.Close()
	actual, err := trustStoreIdentityFromOpenFile(current)
	if err != nil {
		return err
	}
	if !sameTrustStoreKernelObject(expected, actual) {
		return fmt.Errorf("FFU trust-store directory %q was substituted", name)
	}
	return nil
}

func ensureTrustStoreRootIdentity(path string, root *os.File, expected trustStoreFileIdentity) error {
	opened, err := trustStoreIdentityFromOpenFile(root)
	if err != nil {
		return err
	}
	if !sameTrustStoreKernelObject(expected, opened) {
		return errors.New("FFU trust-store root descriptor changed during transaction")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect FFU trust-store root path: %w", err)
	}
	current, err := trustStoreIdentityFromInfo(info)
	if err != nil {
		return err
	}
	if !sameTrustStoreKernelObject(expected, current) {
		return errors.New("FFU trust-store root path was substituted during transaction")
	}
	return nil
}

func validateTrustStoreDirectoryIdentity(identity trustStoreFileIdentity, label string) error {
	if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%s is not a directory", label)
	}
	if identity.uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by the current effective user", label)
	}
	permissions := os.FileMode(identity.mode).Perm()
	if permissions != 0o700 && permissions != 0o500 {
		return fmt.Errorf("%s mode must be 0700 or 0500", label)
	}
	return nil
}

func validateTrustStoreRegularIdentity(identity trustStoreFileIdentity, expectedPerm os.FileMode, label string) error {
	if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("%s is not a regular file", label)
	}
	if identity.uid != uint32(os.Geteuid()) || identity.nlink != 1 {
		return fmt.Errorf("%s has unsafe ownership or hard-link count", label)
	}
	if os.FileMode(identity.mode).Perm() != expectedPerm {
		return fmt.Errorf("%s mode must be %04o", label, expectedPerm)
	}
	return nil
}

func trustStoreIdentityFromInfo(info os.FileInfo) (trustStoreFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return trustStoreFileIdentity{}, errors.New("FFU trust-store path has unsupported filesystem metadata")
	}
	return trustStoreFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, mode: stat.Mode, size: stat.Size,
		modifiedNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
		changedNS:  stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec,
		uid:        stat.Uid, nlink: uint64(stat.Nlink),
	}, nil
}

func trustStoreIdentityFromOpenFile(file *os.File) (trustStoreFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return trustStoreFileIdentity{}, err
	}
	return trustStoreIdentityFromInfo(info)
}

func sameTrustStoreKernelObject(left, right trustStoreFileIdentity) bool {
	return left.device == right.device && left.inode == right.inode && left.mode&syscall.S_IFMT == right.mode&syscall.S_IFMT
}

func sameTrustStoreStableObject(left, right trustStoreFileIdentity) bool {
	return sameTrustStoreKernelObject(left, right) && left.size == right.size && left.modifiedNS == right.modifiedNS && left.changedNS == right.changedNS && left.uid == right.uid && left.nlink == right.nlink
}

func sameTrustStoreContentObject(left, right trustStoreFileIdentity) bool {
	return sameTrustStoreKernelObject(left, right) && left.size == right.size && left.modifiedNS == right.modifiedNS && left.uid == right.uid && left.nlink == right.nlink
}

func randomTrustStoreName(prefix string) (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func trustStoreDescriptorPath(directory *os.File, name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), name)
}

func syncTrustStoreDirectory(directory *os.File) error {
	return syscall.Fsync(int(directory.Fd()))
}

func equalTrustStoreStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
