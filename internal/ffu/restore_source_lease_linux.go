//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"sync"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const fullFlashSourceLeaseEvidenceSchema = 1

// FullFlashSourceLeaseEvidence binds one kernel-held regular FFU descriptor to
// the already reviewed full-flash and live-target preflight evidence. It does
// not authorize target access or execution.
type FullFlashSourceLeaseEvidence struct {
	Schema                          int                         `json:"schema"`
	Mode                            string                      `json:"mode"`
	SourceIdentity                  sourcefile.Identity         `json:"source_identity"`
	SourceFileSize                  uint64                      `json:"source_file_size"`
	FullFlashTargetPreflightSHA256  string                      `json:"full_flash_target_preflight_sha256"`
	FullFlashValidationPlanSHA256   string                      `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256         string                      `json:"restore_target_plan_sha256"`
	AuthenticatedIntegritySHA256    string                      `json:"authenticated_integrity_sha256"`
	TargetDevicePath                string                      `json:"target_device_path"`
	ExpectedTargetIdentity          string                      `json:"expected_target_identity"`
	TargetSizeBytes                 uint64                      `json:"target_size_bytes"`
	KernelReadLeaseRequired         bool                        `json:"kernel_read_lease_required"`
	KernelReadLeaseHeld             bool                        `json:"kernel_read_lease_held"`
	SourceIdentityRevalidated       bool                        `json:"source_identity_revalidated"`
	FullFlashValidationReproduced   bool                        `json:"full_flash_validation_reproduced"`
	TargetPreflightBound            bool                        `json:"target_preflight_bound"`
	FallbackAllowed                 bool                        `json:"fallback_allowed"`
	TargetAccessPermitted           bool                        `json:"target_access_permitted"`
	ExecutionSupported              bool                        `json:"execution_supported"`
	PlanSHA256                      string                      `json:"plan_sha256"`
	Warnings                        []string                    `json:"warnings"`
	Limitations                     []string                    `json:"limitations"`
}

type fullFlashSourceLeaseSeal struct{}

var issuedFullFlashSourceLeaseSeal = &fullFlashSourceLeaseSeal{}

// FullFlashSourceLease holds the caller-owned FFU descriptor under a Linux
// kernel read lease. Its fields and capability seal are unexported; callers can
// inspect evidence, obtain the lease-derived cancellation context, verify the
// hold, and release it, but cannot obtain a target or write capability.
type FullFlashSourceLease struct {
	mu       sync.Mutex
	file     *os.File
	lease    *sourcefile.ReadLease
	identity sourcefile.Identity
	evidence FullFlashSourceLeaseEvidence
	seal     *fullFlashSourceLeaseSeal
	closed   bool
}

// AcquireAuthenticatedFullFlashSourceLease acquires a mandatory Linux read
// lease on the already-open, identity-pinned regular FFU. While that lease is
// held, it reproduces the complete authenticated full-flash decision and
// requires exact agreement with the reviewed live-target preflight.
//
// Lease fallback is deliberately forbidden for the initial restore provider.
// The target is never opened or modified.
func AcquireAuthenticatedFullFlashSourceLease(
	ctx context.Context,
	file *os.File,
	expectedSource sourcefile.Identity,
	activation TrustBundleActivation,
	evaluationTime time.Time,
	publisherPolicy CatalogPublisherPolicy,
	targetRequest RestoreTargetRequest,
	expectedPreflight FullFlashTargetPreflightPlan,
) (*FullFlashSourceLease, error) {
	if ctx == nil {
		return nil, errors.New("FFU source-lease context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, errors.New("FFU source file is nil")
	}
	if err := validateFullFlashTargetPreflightPlan(expectedPreflight); err != nil {
		return nil, fmt.Errorf("validate expected FFU target preflight: %w", err)
	}
	if expectedSource.Size <= 0 {
		return nil, errors.New("FFU source identity has a non-positive size")
	}
	if uint64(expectedSource.Size) != expectedPreflight.SourceFileSize {
		return nil, errors.New("FFU source identity size differs from target-preflight evidence")
	}
	actual, err := sourcefile.IdentityOf(file)
	if err != nil {
		return nil, err
	}
	if actual != expectedSource {
		return nil, errors.New("opened FFU source does not match the reviewed identity")
	}
	if err := sourcefile.VerifyPinned(file, expectedSource); err != nil {
		return nil, err
	}

	lease, err := sourcefile.AcquireReadLease(ctx, file, expectedSource)
	if err != nil {
		return nil, fmt.Errorf("acquire mandatory Linux FFU source read lease: %w", err)
	}
	cleanupLease := true
	defer func() {
		if cleanupLease {
			_ = lease.Close()
		}
	}()

	leaseContext := lease.Context()
	_, validation, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		leaseContext,
		file,
		uint64(expectedSource.Size),
		activation,
		evaluationTime,
		publisherPolicy,
		targetRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("reproduce authenticated FFU under source lease: %w", err)
	}
	if validation.PlanSHA256 != expectedPreflight.FullFlashValidationPlanSHA256 ||
		validation.RestoreTargetPlanSHA256 != expectedPreflight.RestoreTargetPlanSHA256 ||
		validation.AuthenticatedIntegrityPlanSHA256 != expectedPreflight.AuthenticatedIntegritySHA256 ||
		validation.DevicePath != expectedPreflight.DevicePath ||
		validation.ExpectedTargetIdentity != expectedPreflight.ExpectedTargetIdentity ||
		validation.TargetSizeBytes != expectedPreflight.TargetSizeBytes {
		return nil, errors.New("leased FFU authentication does not reproduce the reviewed target preflight")
	}
	if err := sourcefile.VerifyPinned(file, expectedSource); err != nil {
		return nil, err
	}
	if err := lease.Check(); err != nil {
		return nil, err
	}

	evidence := FullFlashSourceLeaseEvidence{
		Schema:                         fullFlashSourceLeaseEvidenceSchema,
		Mode:                           "ffu-authenticated-source-lease",
		SourceIdentity:                 expectedSource,
		SourceFileSize:                 uint64(expectedSource.Size),
		FullFlashTargetPreflightSHA256: expectedPreflight.PlanSHA256,
		FullFlashValidationPlanSHA256:  validation.PlanSHA256,
		RestoreTargetPlanSHA256:        validation.RestoreTargetPlanSHA256,
		AuthenticatedIntegritySHA256:   validation.AuthenticatedIntegrityPlanSHA256,
		TargetDevicePath:               validation.DevicePath,
		ExpectedTargetIdentity:         validation.ExpectedTargetIdentity,
		TargetSizeBytes:                validation.TargetSizeBytes,
		KernelReadLeaseRequired:        true,
		KernelReadLeaseHeld:            true,
		SourceIdentityRevalidated:      true,
		FullFlashValidationReproduced:  true,
		TargetPreflightBound:           true,
		FallbackAllowed:                false,
		TargetAccessPermitted:          false,
		ExecutionSupported:             false,
		Warnings:                       fullFlashSourceLeaseWarnings(),
		Limitations:                    fullFlashSourceLeaseLimitations(),
	}
	evidence.PlanSHA256 = fullFlashSourceLeaseEvidenceDigest(evidence)
	if err := validateFullFlashSourceLeaseEvidence(evidence); err != nil {
		return nil, err
	}

	session := &FullFlashSourceLease{
		file:     file,
		lease:    lease,
		identity: expectedSource,
		evidence: evidence,
		seal:     issuedFullFlashSourceLeaseSeal,
	}
	cleanupLease = false
	return session, nil
}

// Evidence returns an independently owned copy of the immutable lease evidence.
func (session *FullFlashSourceLease) Evidence() (FullFlashSourceLeaseEvidence, error) {
	if session == nil {
		return FullFlashSourceLeaseEvidence{}, errors.New("FFU source lease is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.validateLocked(); err != nil {
		return FullFlashSourceLeaseEvidence{}, err
	}
	result := session.evidence
	result.Warnings = append([]string(nil), result.Warnings...)
	result.Limitations = append([]string(nil), result.Limitations...)
	return result, nil
}

// LeaseContext returns the lease-derived context. A conflicting writer request
// cancels this context so a future provider can fail closed before or during a
// destructive transaction.
func (session *FullFlashSourceLease) LeaseContext() (context.Context, error) {
	if session == nil {
		return nil, errors.New("FFU source lease is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.validateLocked(); err != nil {
		return nil, err
	}
	return session.lease.Context(), nil
}

// Check verifies both the kernel lease and complete pinned source identity.
func (session *FullFlashSourceLease) Check() error {
	if session == nil {
		return errors.New("FFU source lease is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.validateLocked(); err != nil {
		return err
	}
	if err := session.lease.Check(); err != nil {
		return err
	}
	return sourcefile.VerifyPinned(session.file, session.identity)
}

// Close releases the kernel lease but deliberately leaves the caller-owned file
// descriptor open. It is safe to call more than once.
func (session *FullFlashSourceLease) Close() error {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	if session.seal != issuedFullFlashSourceLeaseSeal || session.lease == nil || session.file == nil {
		return errors.New("invalid FFU source-lease capability")
	}
	session.closed = true
	return session.lease.Close()
}

func (session *FullFlashSourceLease) validateLocked() error {
	if session.closed {
		return errors.New("FFU source lease is closed")
	}
	if session.seal != issuedFullFlashSourceLeaseSeal || session.lease == nil || session.file == nil {
		return errors.New("invalid FFU source-lease capability")
	}
	return validateFullFlashSourceLeaseEvidence(session.evidence)
}

func validateFullFlashSourceLeaseEvidence(evidence FullFlashSourceLeaseEvidence) error {
	if evidence.Schema != fullFlashSourceLeaseEvidenceSchema || evidence.Mode != "ffu-authenticated-source-lease" || !evidence.KernelReadLeaseRequired || !evidence.KernelReadLeaseHeld || !evidence.SourceIdentityRevalidated || !evidence.FullFlashValidationReproduced || !evidence.TargetPreflightBound || evidence.FallbackAllowed || evidence.TargetAccessPermitted || evidence.ExecutionSupported {
		return errors.New("invalid FFU source-lease evidence envelope")
	}
	if evidence.SourceIdentity.Size <= 0 || uint64(evidence.SourceIdentity.Size) != evidence.SourceFileSize || evidence.TargetSizeBytes == 0 {
		return errors.New("FFU source-lease size evidence is inconsistent")
	}
	for _, value := range []string{
		evidence.FullFlashTargetPreflightSHA256,
		evidence.FullFlashValidationPlanSHA256,
		evidence.RestoreTargetPlanSHA256,
		evidence.AuthenticatedIntegritySHA256,
		evidence.ExpectedTargetIdentity,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU source-lease evidence contains an invalid SHA-256 identifier")
		}
	}
	if _, err := validateRestoreTargetRequest(RestoreTargetRequest{
		DevicePath:             evidence.TargetDevicePath,
		ExpectedTargetIdentity: evidence.ExpectedTargetIdentity,
		TargetSizeBytes:        evidence.TargetSizeBytes,
		LogicalSectorSizeBytes: 512,
		PhysicalSectorSizeBytes: 512,
	}); err != nil {
		// Only path, identity, and non-zero target size are relevant here. The live
		// sector geometry remains bound by the preflight digest rather than copied.
		if evidence.TargetDevicePath == "" || evidence.ExpectedTargetIdentity == "" || evidence.TargetSizeBytes == 0 {
			return err
		}
	}
	if !equalRestoreStrings(evidence.Warnings, fullFlashSourceLeaseWarnings()) || !equalRestoreStrings(evidence.Limitations, fullFlashSourceLeaseLimitations()) || evidence.PlanSHA256 != fullFlashSourceLeaseEvidenceDigest(evidence) {
		return errors.New("FFU source-lease evidence, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashSourceLeaseWarnings() []string {
	return []string{
		"The authenticated FFU source is held read-only by a Linux kernel lease; any conflicting writer request invalidates the operation.",
		"The source lease must remain held through administrator authentication, target acquisition, every write, flush, and required readback.",
		"The target has not been opened and this source capability grants no permission to unmount or modify any device.",
	}
}

func fullFlashSourceLeaseLimitations() []string {
	return []string{
		"lease fallback is forbidden for the initial FFU provider",
		"the caller retains ownership of the source file descriptor",
		"target open, guarded unmount, exclusive locking, final revalidation, writing, cancellation reporting, flush, and readback remain outside this boundary",
		"execution remains disabled",
	}
}

func fullFlashSourceLeaseEvidenceDigest(evidence FullFlashSourceLeaseEvidence) string {
	digest := sha256.New()
	writeSourceLeaseUint64(digest, uint64(evidence.Schema))
	writeSourceLeaseString(digest, evidence.Mode)
	identityJSON, _ := json.Marshal(evidence.SourceIdentity)
	writeSourceLeaseBytes(digest, identityJSON)
	writeSourceLeaseUint64(digest, evidence.SourceFileSize)
	writeSourceLeaseString(digest, evidence.FullFlashTargetPreflightSHA256)
	writeSourceLeaseString(digest, evidence.FullFlashValidationPlanSHA256)
	writeSourceLeaseString(digest, evidence.RestoreTargetPlanSHA256)
	writeSourceLeaseString(digest, evidence.AuthenticatedIntegritySHA256)
	writeSourceLeaseString(digest, evidence.TargetDevicePath)
	writeSourceLeaseString(digest, evidence.ExpectedTargetIdentity)
	writeSourceLeaseUint64(digest, evidence.TargetSizeBytes)
	writeSourceLeaseBool(digest, evidence.KernelReadLeaseRequired)
	writeSourceLeaseBool(digest, evidence.KernelReadLeaseHeld)
	writeSourceLeaseBool(digest, evidence.SourceIdentityRevalidated)
	writeSourceLeaseBool(digest, evidence.FullFlashValidationReproduced)
	writeSourceLeaseBool(digest, evidence.TargetPreflightBound)
	writeSourceLeaseBool(digest, evidence.FallbackAllowed)
	writeSourceLeaseBool(digest, evidence.TargetAccessPermitted)
	writeSourceLeaseBool(digest, evidence.ExecutionSupported)
	for _, warning := range evidence.Warnings {
		writeSourceLeaseString(digest, warning)
	}
	for _, limitation := range evidence.Limitations {
		writeSourceLeaseString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeSourceLeaseUint64(digest hash.Hash, value uint64) { writePreflightUint64(digest, value) }
func writeSourceLeaseString(digest hash.Hash, value string) { writePreflightString(digest, value) }
func writeSourceLeaseBool(digest hash.Hash, value bool)     { writePreflightBool(digest, value) }
func writeSourceLeaseBytes(digest hash.Hash, value []byte) {
	writeSourceLeaseUint64(digest, uint64(len(value)))
	_, _ = digest.Write(value)
}
