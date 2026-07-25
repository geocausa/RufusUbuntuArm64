//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
)

const (
	fullFlashConfirmationEvidenceSchema = 1
	maxFullFlashConfirmationBytes       = 4096
)

// FullFlashConfirmationEvidence proves that the exact target-and-capacity
// phrase was supplied while the authenticated source lease and exclusive target
// session were both healthy. It grants no mutation or execution authority.
type FullFlashConfirmationEvidence struct {
	Schema                         int      `json:"schema"`
	Mode                           string   `json:"mode"`
	TargetSessionEvidenceSHA256    string   `json:"target_session_evidence_sha256"`
	SourceLeaseEvidenceSHA256      string   `json:"source_lease_evidence_sha256"`
	FullFlashTargetPreflightSHA256 string   `json:"full_flash_target_preflight_sha256"`
	FullFlashValidationPlanSHA256  string   `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256        string   `json:"restore_target_plan_sha256"`
	AuthenticatedIntegritySHA256   string   `json:"authenticated_integrity_sha256"`
	DevicePath                     string   `json:"device_path"`
	ExpectedTargetIdentity         string   `json:"expected_target_identity"`
	TargetSizeBytes                uint64   `json:"target_size_bytes"`
	MutationBytes                  uint64   `json:"mutation_bytes"`
	ExpectedConfirmationPhrase     string   `json:"expected_confirmation_phrase"`
	ConfirmationPhraseSHA256       string   `json:"confirmation_phrase_sha256"`
	ConfirmationExactMatch         bool     `json:"confirmation_exact_match"`
	ConfirmationConsumed           bool     `json:"confirmation_consumed"`
	SourceLeaseHeld                bool     `json:"source_lease_held"`
	TargetSessionHeld              bool     `json:"target_session_held"`
	TargetAccessAcquired           bool     `json:"target_access_acquired"`
	GuardedUnmountPerformed        bool     `json:"guarded_unmount_performed"`
	MutationPermitted              bool     `json:"mutation_permitted"`
	ExecutionSupported             bool     `json:"execution_supported"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Warnings                       []string `json:"warnings"`
	Limitations                    []string `json:"limitations"`
}

type fullFlashConfirmationSeal struct{}

var issuedFullFlashConfirmationSeal = &fullFlashConfirmationSeal{}

// FullFlashDestructiveConfirmation is an unexported-seal capability that binds
// the exact reviewed destructive phrase to one still-live target session. It
// intentionally exposes no source or target descriptor and no mutation API.
type FullFlashDestructiveConfirmation struct {
	mu       sync.Mutex
	target   *FullFlashTargetSession
	evidence FullFlashConfirmationEvidence
	seal     *fullFlashConfirmationSeal
}

// ConfirmExclusiveFullFlashTarget verifies the exact confirmation phrase only
// after the authenticated source lease and exclusive target session have both
// passed live rechecks. The phrase is compared byte-for-byte; whitespace,
// casing, path, and decimal capacity changes are refused.
func ConfirmExclusiveFullFlashTarget(
	ctx context.Context,
	targetSession *FullFlashTargetSession,
	confirmation string,
) (*FullFlashDestructiveConfirmation, error) {
	if ctx == nil {
		return nil, errors.New("FFU destructive-confirmation context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if targetSession == nil {
		return nil, errors.New("FFU exclusive target session is nil")
	}
	if len(confirmation) == 0 || len(confirmation) > maxFullFlashConfirmationBytes {
		return nil, errors.New("FFU destructive confirmation has an invalid length")
	}
	if err := targetSession.Check(); err != nil {
		return nil, fmt.Errorf("check FFU capabilities before confirmation: %w", err)
	}
	before, err := targetSession.Evidence()
	if err != nil {
		return nil, err
	}
	expected := expectedFullFlashConfirmationPhrase(before.DevicePath, before.TargetSizeBytes)
	if len(confirmation) != len(expected) || subtle.ConstantTimeCompare([]byte(confirmation), []byte(expected)) != 1 {
		return nil, errors.New("FFU destructive confirmation does not exactly match the reviewed target and capacity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := targetSession.Check(); err != nil {
		return nil, fmt.Errorf("recheck FFU capabilities after confirmation: %w", err)
	}
	after, err := targetSession.Evidence()
	if err != nil {
		return nil, err
	}
	if after.PlanSHA256 != before.PlanSHA256 || after.SourceLeaseEvidenceSHA256 != before.SourceLeaseEvidenceSHA256 || after.DevicePath != before.DevicePath || after.ExpectedTargetIdentity != before.ExpectedTargetIdentity || after.TargetSizeBytes != before.TargetSizeBytes || after.MutationBytes != before.MutationBytes {
		return nil, errors.New("FFU target-session evidence changed while confirmation was evaluated")
	}

	confirmationDigest := sha256.Sum256([]byte(confirmation))
	evidence := FullFlashConfirmationEvidence{
		Schema:                         fullFlashConfirmationEvidenceSchema,
		Mode:                           "ffu-exact-destructive-confirmation",
		TargetSessionEvidenceSHA256:    after.PlanSHA256,
		SourceLeaseEvidenceSHA256:      after.SourceLeaseEvidenceSHA256,
		FullFlashTargetPreflightSHA256: after.FullFlashTargetPreflightSHA256,
		FullFlashValidationPlanSHA256:  after.FullFlashValidationPlanSHA256,
		RestoreTargetPlanSHA256:        after.RestoreTargetPlanSHA256,
		AuthenticatedIntegritySHA256:   after.AuthenticatedIntegritySHA256,
		DevicePath:                     after.DevicePath,
		ExpectedTargetIdentity:         after.ExpectedTargetIdentity,
		TargetSizeBytes:                after.TargetSizeBytes,
		MutationBytes:                  after.MutationBytes,
		ExpectedConfirmationPhrase:     expected,
		ConfirmationPhraseSHA256:       hex.EncodeToString(confirmationDigest[:]),
		ConfirmationExactMatch:         true,
		ConfirmationConsumed:           true,
		SourceLeaseHeld:                true,
		TargetSessionHeld:              true,
		TargetAccessAcquired:           true,
		GuardedUnmountPerformed:        false,
		MutationPermitted:              false,
		ExecutionSupported:             false,
		Warnings:                       fullFlashConfirmationWarnings(),
		Limitations:                    fullFlashConfirmationLimitations(),
	}
	evidence.PlanSHA256 = fullFlashConfirmationEvidenceDigest(evidence)
	if err := validateFullFlashConfirmationEvidence(evidence); err != nil {
		return nil, err
	}
	return &FullFlashDestructiveConfirmation{
		target: targetSession,
		evidence: evidence,
		seal: issuedFullFlashConfirmationSeal,
	}, nil
}

// Evidence returns an independently owned copy of the exact-confirmation
// evidence. It contains no descriptor or operation capability.
func (confirmation *FullFlashDestructiveConfirmation) Evidence() (FullFlashConfirmationEvidence, error) {
	if confirmation == nil {
		return FullFlashConfirmationEvidence{}, errors.New("FFU destructive confirmation is nil")
	}
	confirmation.mu.Lock()
	defer confirmation.mu.Unlock()
	if err := confirmation.validateLocked(); err != nil {
		return FullFlashConfirmationEvidence{}, err
	}
	result := confirmation.evidence
	result.Warnings = append([]string(nil), result.Warnings...)
	result.Limitations = append([]string(nil), result.Limitations...)
	return result, nil
}

// Check proves that the exact target session bound during phrase verification
// remains live and unchanged. It still grants no mutation authority.
func (confirmation *FullFlashDestructiveConfirmation) Check() error {
	if confirmation == nil {
		return errors.New("FFU destructive confirmation is nil")
	}
	confirmation.mu.Lock()
	defer confirmation.mu.Unlock()
	if err := confirmation.validateLocked(); err != nil {
		return err
	}
	if err := confirmation.target.Check(); err != nil {
		return err
	}
	targetEvidence, err := confirmation.target.Evidence()
	if err != nil {
		return err
	}
	if targetEvidence.PlanSHA256 != confirmation.evidence.TargetSessionEvidenceSHA256 || targetEvidence.SourceLeaseEvidenceSHA256 != confirmation.evidence.SourceLeaseEvidenceSHA256 || targetEvidence.DevicePath != confirmation.evidence.DevicePath || targetEvidence.ExpectedTargetIdentity != confirmation.evidence.ExpectedTargetIdentity || targetEvidence.TargetSizeBytes != confirmation.evidence.TargetSizeBytes || targetEvidence.MutationBytes != confirmation.evidence.MutationBytes {
		return errors.New("FFU target session no longer matches destructive-confirmation evidence")
	}
	return nil
}

func (confirmation *FullFlashDestructiveConfirmation) validateLocked() error {
	if confirmation.seal != issuedFullFlashConfirmationSeal || confirmation.target == nil {
		return errors.New("invalid FFU destructive-confirmation capability")
	}
	return validateFullFlashConfirmationEvidence(confirmation.evidence)
}

func expectedFullFlashConfirmationPhrase(devicePath string, targetSize uint64) string {
	return fmt.Sprintf("RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES", devicePath, targetSize)
}

func validateFullFlashConfirmationEvidence(evidence FullFlashConfirmationEvidence) error {
	if evidence.Schema != fullFlashConfirmationEvidenceSchema || evidence.Mode != "ffu-exact-destructive-confirmation" || !evidence.ConfirmationExactMatch || !evidence.ConfirmationConsumed || !evidence.SourceLeaseHeld || !evidence.TargetSessionHeld || !evidence.TargetAccessAcquired || evidence.GuardedUnmountPerformed || evidence.MutationPermitted || evidence.ExecutionSupported {
		return errors.New("invalid FFU destructive-confirmation evidence envelope")
	}
	for _, value := range []string{
		evidence.TargetSessionEvidenceSHA256,
		evidence.SourceLeaseEvidenceSHA256,
		evidence.FullFlashTargetPreflightSHA256,
		evidence.FullFlashValidationPlanSHA256,
		evidence.RestoreTargetPlanSHA256,
		evidence.AuthenticatedIntegritySHA256,
		evidence.ExpectedTargetIdentity,
		evidence.ConfirmationPhraseSHA256,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU destructive-confirmation evidence contains an invalid SHA-256 identifier")
		}
	}
	if strings.TrimSpace(evidence.DevicePath) != evidence.DevicePath || !strings.HasPrefix(evidence.DevicePath, "/dev/") || evidence.TargetSizeBytes == 0 || evidence.MutationBytes == 0 || evidence.MutationBytes > evidence.TargetSizeBytes {
		return errors.New("FFU destructive-confirmation target evidence is inconsistent")
	}
	expected := expectedFullFlashConfirmationPhrase(evidence.DevicePath, evidence.TargetSizeBytes)
	if evidence.ExpectedConfirmationPhrase != expected {
		return errors.New("FFU destructive-confirmation phrase evidence was altered")
	}
	phraseDigest := sha256.Sum256([]byte(expected))
	if evidence.ConfirmationPhraseSHA256 != hex.EncodeToString(phraseDigest[:]) {
		return errors.New("FFU destructive-confirmation phrase digest was altered")
	}
	if !equalRestoreStrings(evidence.Warnings, fullFlashConfirmationWarnings()) || !equalRestoreStrings(evidence.Limitations, fullFlashConfirmationLimitations()) || evidence.PlanSHA256 != fullFlashConfirmationEvidenceDigest(evidence) {
		return errors.New("FFU destructive-confirmation evidence, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashConfirmationWarnings() []string {
	return []string{
		"The exact target path and byte capacity were confirmed while the authenticated source and exclusive target capabilities were healthy.",
		"Confirmation does not authorize mutation; a separate execution boundary must still define and qualify every destructive phase.",
		"Closing or invalidating the source lease or target session invalidates this confirmation capability.",
	}
}

func fullFlashConfirmationLimitations() []string {
	return []string{
		"confirmation is bound only to the currently held source and target capabilities",
		"guarded unmount remains outside this boundary and was not performed",
		"write ordering, mutation authorization, cancellation reporting, flush, readback, and result publication remain unresolved",
		"mutation and execution remain disabled",
	}
}

func fullFlashConfirmationEvidenceDigest(evidence FullFlashConfirmationEvidence) string {
	digest := sha256.New()
	writeConfirmationUint64(digest, uint64(evidence.Schema))
	writeConfirmationString(digest, evidence.Mode)
	writeConfirmationString(digest, evidence.TargetSessionEvidenceSHA256)
	writeConfirmationString(digest, evidence.SourceLeaseEvidenceSHA256)
	writeConfirmationString(digest, evidence.FullFlashTargetPreflightSHA256)
	writeConfirmationString(digest, evidence.FullFlashValidationPlanSHA256)
	writeConfirmationString(digest, evidence.RestoreTargetPlanSHA256)
	writeConfirmationString(digest, evidence.AuthenticatedIntegritySHA256)
	writeConfirmationString(digest, evidence.DevicePath)
	writeConfirmationString(digest, evidence.ExpectedTargetIdentity)
	writeConfirmationUint64(digest, evidence.TargetSizeBytes)
	writeConfirmationUint64(digest, evidence.MutationBytes)
	writeConfirmationString(digest, evidence.ExpectedConfirmationPhrase)
	writeConfirmationString(digest, evidence.ConfirmationPhraseSHA256)
	writeConfirmationBool(digest, evidence.ConfirmationExactMatch)
	writeConfirmationBool(digest, evidence.ConfirmationConsumed)
	writeConfirmationBool(digest, evidence.SourceLeaseHeld)
	writeConfirmationBool(digest, evidence.TargetSessionHeld)
	writeConfirmationBool(digest, evidence.TargetAccessAcquired)
	writeConfirmationBool(digest, evidence.GuardedUnmountPerformed)
	writeConfirmationBool(digest, evidence.MutationPermitted)
	writeConfirmationBool(digest, evidence.ExecutionSupported)
	for _, warning := range evidence.Warnings {
		writeConfirmationString(digest, warning)
	}
	for _, limitation := range evidence.Limitations {
		writeConfirmationString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeConfirmationUint64(digest hash.Hash, value uint64) { writeTargetSessionUint64(digest, value) }
func writeConfirmationString(digest hash.Hash, value string) { writeTargetSessionString(digest, value) }
func writeConfirmationBool(digest hash.Hash, value bool)     { writeTargetSessionBool(digest, value) }
