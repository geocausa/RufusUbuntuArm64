//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"path/filepath"
	"strings"
	"sync"
)

const fullFlashMutationAuthorizationEvidenceSchema = 1

// FullFlashMutationAuthorizationEvidence proves that one exact destructive
// confirmation capability was correlated with a freshly reproduced
// single-phase write-order plan while the source lease and exclusive target
// session remained healthy. Only the sealed capability carries mutation
// authority; execution remains unsupported.
type FullFlashMutationAuthorizationEvidence struct {
	Schema                         int      `json:"schema"`
	Mode                           string   `json:"mode"`
	ConfirmationEvidenceSHA256     string   `json:"confirmation_evidence_sha256"`
	TargetSessionEvidenceSHA256    string   `json:"target_session_evidence_sha256"`
	SourceLeaseEvidenceSHA256      string   `json:"source_lease_evidence_sha256"`
	FullFlashTargetPreflightSHA256 string   `json:"full_flash_target_preflight_sha256"`
	WriteOrderPlanSHA256           string   `json:"write_order_plan_sha256"`
	FullFlashValidationPlanSHA256  string   `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256        string   `json:"restore_target_plan_sha256"`
	DescriptorPlanSHA256           string   `json:"descriptor_plan_sha256"`
	AuthenticatedIntegritySHA256   string   `json:"authenticated_integrity_sha256"`
	CatalogSHA256                  string   `json:"catalog_sha256"`
	HashTableSHA256                string   `json:"hash_table_sha256"`
	DevicePath                     string   `json:"device_path"`
	ExpectedTargetIdentity         string   `json:"expected_target_identity"`
	TargetSizeBytes                uint64   `json:"target_size_bytes"`
	StoreBlockSizeBytes            uint64   `json:"store_block_size_bytes"`
	OperationCount                 uint64   `json:"operation_count"`
	MutationBytes                  uint64   `json:"mutation_bytes"`
	ConfirmationPhrase             string   `json:"confirmation_phrase"`
	ConfirmationSatisfied          bool     `json:"confirmation_satisfied"`
	SourceLeaseHeld                bool     `json:"source_lease_held"`
	TargetSessionHeld              bool     `json:"target_session_held"`
	TargetAccessAcquired           bool     `json:"target_access_acquired"`
	SinglePhaseWriteOrderResolved  bool     `json:"single_phase_write_order_resolved"`
	StagedGPTProfileAllowed        bool     `json:"staged_gpt_profile_allowed"`
	GuardedUnmountPerformed        bool     `json:"guarded_unmount_performed"`
	OneShotExecutionRequired       bool     `json:"one_shot_execution_required"`
	AuthorizationConsumed          bool     `json:"authorization_consumed"`
	MutationPermitted              bool     `json:"mutation_permitted"`
	ExecutionSupported             bool     `json:"execution_supported"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Warnings                       []string `json:"warnings"`
	Limitations                    []string `json:"limitations"`
}

type fullFlashMutationAuthorizationSeal struct{}

var issuedFullFlashMutationAuthorizationSeal = &fullFlashMutationAuthorizationSeal{}

// FullFlashMutationAuthorization is an unexported-seal capability. It retains
// the live destructive-confirmation capability and the internally reproduced
// write order, but exposes no source or target descriptor and no mutation API.
type FullFlashMutationAuthorization struct {
	mu           sync.Mutex
	confirmation *FullFlashDestructiveConfirmation
	writeOrder   FullFlashWriteOrderPlan
	evidence     FullFlashMutationAuthorizationEvidence
	seal         *fullFlashMutationAuthorizationSeal
}

// AuthorizeSinglePhaseFullFlashMutation advances mutation authority only after
// the exact confirmation capability is live and the single-phase write order is
// freshly reproduced from its prerequisite plans. No caller-supplied write-order
// plan is trusted, and this function performs no target mutation.
func AuthorizeSinglePhaseFullFlashMutation(
	ctx context.Context,
	confirmation *FullFlashDestructiveConfirmation,
	descriptor DescriptorPlan,
	target RestoreTargetPlan,
	full FullFlashValidationPlan,
) (*FullFlashMutationAuthorization, error) {
	if ctx == nil {
		return nil, errors.New("FFU mutation-authorization context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if confirmation == nil {
		return nil, errors.New("FFU destructive-confirmation capability is nil")
	}
	if err := confirmation.Check(); err != nil {
		return nil, fmt.Errorf("check FFU confirmation before mutation authorization: %w", err)
	}
	before, err := confirmation.Evidence()
	if err != nil {
		return nil, err
	}
	writeOrder, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
	if err != nil {
		return nil, err
	}
	if err := correlateFullFlashMutationAuthorization(before, writeOrder, target, full); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := confirmation.Check(); err != nil {
		return nil, fmt.Errorf("recheck FFU confirmation after write-order reproduction: %w", err)
	}
	after, err := confirmation.Evidence()
	if err != nil {
		return nil, err
	}
	if after.PlanSHA256 != before.PlanSHA256 || after.TargetSessionEvidenceSHA256 != before.TargetSessionEvidenceSHA256 || after.SourceLeaseEvidenceSHA256 != before.SourceLeaseEvidenceSHA256 || after.FullFlashTargetPreflightSHA256 != before.FullFlashTargetPreflightSHA256 || after.FullFlashValidationPlanSHA256 != before.FullFlashValidationPlanSHA256 || after.RestoreTargetPlanSHA256 != before.RestoreTargetPlanSHA256 || after.AuthenticatedIntegritySHA256 != before.AuthenticatedIntegritySHA256 || after.DevicePath != before.DevicePath || after.ExpectedTargetIdentity != before.ExpectedTargetIdentity || after.TargetSizeBytes != before.TargetSizeBytes || after.MutationBytes != before.MutationBytes || after.ExpectedConfirmationPhrase != before.ExpectedConfirmationPhrase {
		return nil, errors.New("FFU destructive-confirmation evidence changed during mutation authorization")
	}
	if err := correlateFullFlashMutationAuthorization(after, writeOrder, target, full); err != nil {
		return nil, err
	}

	evidence := FullFlashMutationAuthorizationEvidence{
		Schema:                         fullFlashMutationAuthorizationEvidenceSchema,
		Mode:                           "ffu-single-phase-mutation-authorization",
		ConfirmationEvidenceSHA256:     after.PlanSHA256,
		TargetSessionEvidenceSHA256:    after.TargetSessionEvidenceSHA256,
		SourceLeaseEvidenceSHA256:      after.SourceLeaseEvidenceSHA256,
		FullFlashTargetPreflightSHA256: after.FullFlashTargetPreflightSHA256,
		WriteOrderPlanSHA256:           writeOrder.PlanSHA256,
		FullFlashValidationPlanSHA256:  full.PlanSHA256,
		RestoreTargetPlanSHA256:        target.PlanSHA256,
		DescriptorPlanSHA256:           descriptor.PlanSHA256,
		AuthenticatedIntegritySHA256:   full.AuthenticatedIntegrityPlanSHA256,
		CatalogSHA256:                  full.CatalogSHA256,
		HashTableSHA256:                full.HashTableSHA256,
		DevicePath:                     full.DevicePath,
		ExpectedTargetIdentity:         full.ExpectedTargetIdentity,
		TargetSizeBytes:                full.TargetSizeBytes,
		StoreBlockSizeBytes:            full.StoreBlockSizeBytes,
		OperationCount:                 writeOrder.OperationCount,
		MutationBytes:                  writeOrder.MutationBytes,
		ConfirmationPhrase:             full.ConfirmationPhrase,
		ConfirmationSatisfied:          true,
		SourceLeaseHeld:                true,
		TargetSessionHeld:              true,
		TargetAccessAcquired:           true,
		SinglePhaseWriteOrderResolved:  true,
		StagedGPTProfileAllowed:        false,
		GuardedUnmountPerformed:        false,
		OneShotExecutionRequired:       true,
		AuthorizationConsumed:          false,
		MutationPermitted:              true,
		ExecutionSupported:             false,
		Warnings:                       fullFlashMutationAuthorizationWarnings(),
		Limitations:                    fullFlashMutationAuthorizationLimitations(),
	}
	evidence.PlanSHA256 = fullFlashMutationAuthorizationEvidenceDigest(evidence)
	if err := validateFullFlashMutationAuthorizationEvidence(evidence); err != nil {
		return nil, err
	}
	return &FullFlashMutationAuthorization{
		confirmation: confirmation,
		writeOrder:   writeOrder,
		evidence:     evidence,
		seal:         issuedFullFlashMutationAuthorizationSeal,
	}, nil
}

func correlateFullFlashMutationAuthorization(
	confirmation FullFlashConfirmationEvidence,
	writeOrder FullFlashWriteOrderPlan,
	target RestoreTargetPlan,
	full FullFlashValidationPlan,
) error {
	if err := validateFullFlashConfirmationEvidence(confirmation); err != nil {
		return err
	}
	if err := validateFullFlashWriteOrderPlan(writeOrder); err != nil {
		return err
	}
	if confirmation.FullFlashValidationPlanSHA256 != full.PlanSHA256 || confirmation.RestoreTargetPlanSHA256 != target.PlanSHA256 || confirmation.AuthenticatedIntegritySHA256 != full.AuthenticatedIntegrityPlanSHA256 {
		return errors.New("FFU confirmation does not bind the supplied full-flash prerequisites")
	}
	if confirmation.DevicePath != full.DevicePath || confirmation.DevicePath != target.DevicePath || confirmation.ExpectedTargetIdentity != full.ExpectedTargetIdentity || confirmation.ExpectedTargetIdentity != target.ExpectedTargetIdentity || confirmation.TargetSizeBytes != full.TargetSizeBytes || confirmation.TargetSizeBytes != target.TargetSizeBytes || confirmation.MutationBytes != full.MutationBytes || confirmation.MutationBytes != target.MutationBytes {
		return errors.New("FFU confirmation does not bind the supplied target and mutation scope")
	}
	if confirmation.ExpectedConfirmationPhrase != full.ConfirmationPhrase || writeOrder.ConfirmationPhrase != full.ConfirmationPhrase {
		return errors.New("FFU confirmation and write-order plans disagree on the exact destructive phrase")
	}
	if writeOrder.DescriptorPlanSHA256 != full.DescriptorPlanSHA256 || writeOrder.RestoreTargetPlanSHA256 != target.PlanSHA256 || writeOrder.FullFlashValidationPlanSHA256 != full.PlanSHA256 || writeOrder.AuthenticatedIntegrityPlanSHA256 != full.AuthenticatedIntegrityPlanSHA256 || writeOrder.CatalogSHA256 != full.CatalogSHA256 || writeOrder.HashTableSHA256 != full.HashTableSHA256 {
		return errors.New("FFU reproduced write order does not bind the supplied authenticated plans")
	}
	if writeOrder.DevicePath != full.DevicePath || writeOrder.ExpectedTargetIdentity != full.ExpectedTargetIdentity || writeOrder.TargetSizeBytes != full.TargetSizeBytes || writeOrder.StoreBlockSizeBytes != full.StoreBlockSizeBytes || writeOrder.MutationBytes != full.MutationBytes || !writeOrder.ConfirmationStillRequired || writeOrder.MutationPermitted || writeOrder.ExecutionSupported {
		return errors.New("FFU reproduced write order crossed or disagrees with the mutation-authorization boundary")
	}
	return nil
}

// Evidence returns an independently owned copy of the sealed mutation-
// authorization evidence. It contains no descriptor or write operation.
func (authorization *FullFlashMutationAuthorization) Evidence() (FullFlashMutationAuthorizationEvidence, error) {
	if authorization == nil {
		return FullFlashMutationAuthorizationEvidence{}, errors.New("FFU mutation authorization is nil")
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	if err := authorization.validateLocked(); err != nil {
		return FullFlashMutationAuthorizationEvidence{}, err
	}
	result := authorization.evidence
	result.Warnings = append([]string(nil), result.Warnings...)
	result.Limitations = append([]string(nil), result.Limitations...)
	return result, nil
}

// Check proves that the exact confirmation, source lease, target session, and
// internally reproduced write order remain valid. It does not execute a write.
func (authorization *FullFlashMutationAuthorization) Check() error {
	if authorization == nil {
		return errors.New("FFU mutation authorization is nil")
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	if err := authorization.validateLocked(); err != nil {
		return err
	}
	if err := authorization.confirmation.Check(); err != nil {
		return err
	}
	confirmationEvidence, err := authorization.confirmation.Evidence()
	if err != nil {
		return err
	}
	if confirmationEvidence.PlanSHA256 != authorization.evidence.ConfirmationEvidenceSHA256 || confirmationEvidence.TargetSessionEvidenceSHA256 != authorization.evidence.TargetSessionEvidenceSHA256 || confirmationEvidence.SourceLeaseEvidenceSHA256 != authorization.evidence.SourceLeaseEvidenceSHA256 || confirmationEvidence.FullFlashTargetPreflightSHA256 != authorization.evidence.FullFlashTargetPreflightSHA256 || confirmationEvidence.FullFlashValidationPlanSHA256 != authorization.evidence.FullFlashValidationPlanSHA256 || confirmationEvidence.RestoreTargetPlanSHA256 != authorization.evidence.RestoreTargetPlanSHA256 || confirmationEvidence.AuthenticatedIntegritySHA256 != authorization.evidence.AuthenticatedIntegritySHA256 || confirmationEvidence.DevicePath != authorization.evidence.DevicePath || confirmationEvidence.ExpectedTargetIdentity != authorization.evidence.ExpectedTargetIdentity || confirmationEvidence.TargetSizeBytes != authorization.evidence.TargetSizeBytes || confirmationEvidence.MutationBytes != authorization.evidence.MutationBytes || confirmationEvidence.ExpectedConfirmationPhrase != authorization.evidence.ConfirmationPhrase {
		return errors.New("FFU destructive confirmation no longer matches mutation authorization")
	}
	return validateFullFlashWriteOrderPlan(authorization.writeOrder)
}

func (authorization *FullFlashMutationAuthorization) validateLocked() error {
	if authorization.seal != issuedFullFlashMutationAuthorizationSeal || authorization.confirmation == nil {
		return errors.New("invalid FFU mutation-authorization capability")
	}
	if err := validateFullFlashWriteOrderPlan(authorization.writeOrder); err != nil {
		return err
	}
	if authorization.writeOrder.PlanSHA256 != authorization.evidence.WriteOrderPlanSHA256 || authorization.writeOrder.OperationCount != authorization.evidence.OperationCount || authorization.writeOrder.MutationBytes != authorization.evidence.MutationBytes || authorization.writeOrder.DevicePath != authorization.evidence.DevicePath || authorization.writeOrder.ExpectedTargetIdentity != authorization.evidence.ExpectedTargetIdentity || authorization.writeOrder.TargetSizeBytes != authorization.evidence.TargetSizeBytes || authorization.writeOrder.StoreBlockSizeBytes != authorization.evidence.StoreBlockSizeBytes {
		return errors.New("FFU mutation authorization no longer matches its write-order plan")
	}
	return validateFullFlashMutationAuthorizationEvidence(authorization.evidence)
}

func validateFullFlashMutationAuthorizationEvidence(evidence FullFlashMutationAuthorizationEvidence) error {
	if evidence.Schema != fullFlashMutationAuthorizationEvidenceSchema || evidence.Mode != "ffu-single-phase-mutation-authorization" || !evidence.ConfirmationSatisfied || !evidence.SourceLeaseHeld || !evidence.TargetSessionHeld || !evidence.TargetAccessAcquired || !evidence.SinglePhaseWriteOrderResolved || evidence.StagedGPTProfileAllowed || evidence.GuardedUnmountPerformed || !evidence.OneShotExecutionRequired || evidence.AuthorizationConsumed || !evidence.MutationPermitted || evidence.ExecutionSupported {
		return errors.New("invalid FFU mutation-authorization evidence envelope")
	}
	for _, value := range []string{
		evidence.ConfirmationEvidenceSHA256,
		evidence.TargetSessionEvidenceSHA256,
		evidence.SourceLeaseEvidenceSHA256,
		evidence.FullFlashTargetPreflightSHA256,
		evidence.WriteOrderPlanSHA256,
		evidence.FullFlashValidationPlanSHA256,
		evidence.RestoreTargetPlanSHA256,
		evidence.DescriptorPlanSHA256,
		evidence.AuthenticatedIntegritySHA256,
		evidence.CatalogSHA256,
		evidence.HashTableSHA256,
		evidence.ExpectedTargetIdentity,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU mutation-authorization evidence contains an invalid SHA-256 identifier")
		}
	}
	path := strings.TrimSpace(evidence.DevicePath)
	if path == "" || path != evidence.DevicePath || !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path || evidence.TargetSizeBytes == 0 || evidence.StoreBlockSizeBytes == 0 || evidence.TargetSizeBytes%evidence.StoreBlockSizeBytes != 0 || evidence.OperationCount == 0 || evidence.MutationBytes == 0 || evidence.MutationBytes > evidence.TargetSizeBytes {
		return errors.New("FFU mutation-authorization target, operation, or geometry evidence is inconsistent")
	}
	expectedPhrase := expectedFullFlashConfirmationPhrase(evidence.DevicePath, evidence.TargetSizeBytes)
	if evidence.ConfirmationPhrase != expectedPhrase {
		return errors.New("FFU mutation-authorization confirmation phrase was altered")
	}
	if !equalRestoreStrings(evidence.Warnings, fullFlashMutationAuthorizationWarnings()) || !equalRestoreStrings(evidence.Limitations, fullFlashMutationAuthorizationLimitations()) || evidence.PlanSHA256 != fullFlashMutationAuthorizationEvidenceDigest(evidence) {
		return errors.New("FFU mutation-authorization evidence, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashMutationAuthorizationWarnings() []string {
	return []string{
		"This sealed capability authorizes mutation only for the exact confirmed target and freshly reproduced single-phase write order.",
		"Execution remains disabled; a later one-shot executor must recheck every live capability immediately before the first write.",
		"Once a future executor begins mutation, cancellation or failure may leave the target partially modified and must be reported explicitly.",
		"Software restoration cannot prove physical bootability or complete device health.",
	}
}

func fullFlashMutationAuthorizationLimitations() []string {
	return []string{
		"only the non-staged single-phase FFU profile is eligible",
		"the authorization exposes no source or target descriptor and no read, write, seek, sync, ioctl, unmount, or privilege method",
		"the authorization has not been consumed and performs no target mutation",
		"one-shot execution, cancellation result states, flush, readback, changed-media handling, and provider qualification remain separate gates",
	}
}

func fullFlashMutationAuthorizationEvidenceDigest(evidence FullFlashMutationAuthorizationEvidence) string {
	digest := sha256.New()
	writeMutationAuthorizationUint64(digest, uint64(evidence.Schema))
	writeMutationAuthorizationString(digest, evidence.Mode)
	writeMutationAuthorizationString(digest, evidence.ConfirmationEvidenceSHA256)
	writeMutationAuthorizationString(digest, evidence.TargetSessionEvidenceSHA256)
	writeMutationAuthorizationString(digest, evidence.SourceLeaseEvidenceSHA256)
	writeMutationAuthorizationString(digest, evidence.FullFlashTargetPreflightSHA256)
	writeMutationAuthorizationString(digest, evidence.WriteOrderPlanSHA256)
	writeMutationAuthorizationString(digest, evidence.FullFlashValidationPlanSHA256)
	writeMutationAuthorizationString(digest, evidence.RestoreTargetPlanSHA256)
	writeMutationAuthorizationString(digest, evidence.DescriptorPlanSHA256)
	writeMutationAuthorizationString(digest, evidence.AuthenticatedIntegritySHA256)
	writeMutationAuthorizationString(digest, evidence.CatalogSHA256)
	writeMutationAuthorizationString(digest, evidence.HashTableSHA256)
	writeMutationAuthorizationString(digest, evidence.DevicePath)
	writeMutationAuthorizationString(digest, evidence.ExpectedTargetIdentity)
	writeMutationAuthorizationUint64(digest, evidence.TargetSizeBytes)
	writeMutationAuthorizationUint64(digest, evidence.StoreBlockSizeBytes)
	writeMutationAuthorizationUint64(digest, evidence.OperationCount)
	writeMutationAuthorizationUint64(digest, evidence.MutationBytes)
	writeMutationAuthorizationString(digest, evidence.ConfirmationPhrase)
	writeMutationAuthorizationBool(digest, evidence.ConfirmationSatisfied)
	writeMutationAuthorizationBool(digest, evidence.SourceLeaseHeld)
	writeMutationAuthorizationBool(digest, evidence.TargetSessionHeld)
	writeMutationAuthorizationBool(digest, evidence.TargetAccessAcquired)
	writeMutationAuthorizationBool(digest, evidence.SinglePhaseWriteOrderResolved)
	writeMutationAuthorizationBool(digest, evidence.StagedGPTProfileAllowed)
	writeMutationAuthorizationBool(digest, evidence.GuardedUnmountPerformed)
	writeMutationAuthorizationBool(digest, evidence.OneShotExecutionRequired)
	writeMutationAuthorizationBool(digest, evidence.AuthorizationConsumed)
	writeMutationAuthorizationBool(digest, evidence.MutationPermitted)
	writeMutationAuthorizationBool(digest, evidence.ExecutionSupported)
	for _, warning := range evidence.Warnings {
		writeMutationAuthorizationString(digest, warning)
	}
	for _, limitation := range evidence.Limitations {
		writeMutationAuthorizationString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeMutationAuthorizationUint64(digest hash.Hash, value uint64) {
	writeConfirmationUint64(digest, value)
}

func writeMutationAuthorizationString(digest hash.Hash, value string) {
	writeConfirmationString(digest, value)
}

func writeMutationAuthorizationBool(digest hash.Hash, value bool) {
	writeConfirmationBool(digest, value)
}
