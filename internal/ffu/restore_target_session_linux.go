//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const fullFlashTargetSessionEvidenceSchema = 1

// FullFlashTargetSessionEvidence binds one kernel-exclusive, already-unmounted
// target descriptor to the authenticated source lease and reviewed live target
// preflight. It grants no mutation or execution authority.
type FullFlashTargetSessionEvidence struct {
	Schema                         int      `json:"schema"`
	Mode                           string   `json:"mode"`
	SourceLeaseEvidenceSHA256      string   `json:"source_lease_evidence_sha256"`
	FullFlashTargetPreflightSHA256 string   `json:"full_flash_target_preflight_sha256"`
	FullFlashValidationPlanSHA256  string   `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256        string   `json:"restore_target_plan_sha256"`
	AuthenticatedIntegritySHA256   string   `json:"authenticated_integrity_sha256"`
	DevicePath                     string   `json:"device_path"`
	ExpectedTargetIdentity         string   `json:"expected_target_identity"`
	RediscoveredTargetIdentity     string   `json:"rediscovered_target_identity"`
	TargetSizeBytes                uint64   `json:"target_size_bytes"`
	LogicalSectorSizeBytes         uint64   `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes        uint64   `json:"physical_sector_size_bytes"`
	StoreBlockSizeBytes            uint64   `json:"store_block_size_bytes"`
	ExpectedKernelDeviceID         uint64   `json:"expected_kernel_device_id"`
	ObservedKernelDeviceID         uint64   `json:"observed_kernel_device_id"`
	MajorMinor                     string   `json:"major_minor"`
	MutationBytes                  uint64   `json:"mutation_bytes"`
	SourceLeaseHeld                bool     `json:"source_lease_held"`
	TargetOpenedReadWrite          bool     `json:"target_opened_read_write"`
	KernelExclusiveOpen            bool     `json:"kernel_exclusive_open"`
	NoFollowOpen                   bool     `json:"no_follow_open"`
	MountedTargetsAbsent           bool     `json:"mounted_targets_absent"`
	GuardedUnmountPerformed        bool     `json:"guarded_unmount_performed"`
	TargetDescriptorVerified       bool     `json:"target_descriptor_verified"`
	TargetPolicyRevalidated        bool     `json:"target_policy_revalidated"`
	TargetGeometryRevalidated      bool     `json:"target_geometry_revalidated"`
	SourceOutsideTargetConfirmed   bool     `json:"source_outside_target_confirmed"`
	FixedDiskOverrideAllowed       bool     `json:"fixed_disk_override_allowed"`
	TargetAccessAcquired           bool     `json:"target_access_acquired"`
	MutationPermitted              bool     `json:"mutation_permitted"`
	ExecutionSupported             bool     `json:"execution_supported"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Warnings                       []string `json:"warnings"`
	Limitations                    []string `json:"limitations"`
}

type fullFlashTargetSessionSeal struct{}

var issuedFullFlashTargetSessionSeal = &fullFlashTargetSessionSeal{}

type fullFlashTargetOpenOps struct {
	openTarget          func(string) (*os.File, error)
	verifyOpenTarget    func(*os.File, uint64, uint64) error
	revalidateTarget    func(string, uint64) (device.BlockDevice, uint64, error)
	readSectorGeometry  func(string) (uint64, uint64, error)
	ensureSourceOutside func(*os.File, device.BlockDevice) error
}

var productionFullFlashTargetOpenOps = fullFlashTargetOpenOps{
	openTarget: func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_RDWR|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
	},
	verifyOpenTarget: safety.VerifyOpenDevice,
	revalidateTarget: func(path string, expectedKernelID uint64) (device.BlockDevice, uint64, error) {
		return safety.RevalidateOpenBoundTarget(path, expectedKernelID, false)
	},
	readSectorGeometry: func(deviceName string) (uint64, uint64, error) {
		return readFFUTargetSectorGeometryAt(ffuSysClassBlockRoot, deviceName)
	},
	ensureSourceOutside: safety.EnsureOpenFileNotOnTarget,
}

// FullFlashTargetSession owns one kernel-exclusive target descriptor but exposes
// no descriptor, read, write, seek, sync, or ioctl method. Future mutation code
// must live in this package and pass a separate execution-authorization gate.
type FullFlashTargetSession struct {
	mu       sync.Mutex
	file     *os.File
	source   *FullFlashSourceLease
	preflight FullFlashTargetPreflightPlan
	evidence FullFlashTargetSessionEvidence
	ops      fullFlashTargetOpenOps
	seal     *fullFlashTargetSessionSeal
	closed   bool
}

// AcquireExclusiveFullFlashTarget requires an authenticated source lease and an
// already-unmounted live target preflight. It opens the exact target with Linux
// O_RDWR|O_EXCL|O_NOFOLLOW, verifies the held descriptor and complete current
// policy, and returns a sealed non-mutating capability.
func AcquireExclusiveFullFlashTarget(
	ctx context.Context,
	sourceLease *FullFlashSourceLease,
	expectedPreflight FullFlashTargetPreflightPlan,
) (*FullFlashTargetSession, error) {
	return acquireExclusiveFullFlashTargetWithOps(ctx, sourceLease, expectedPreflight, productionFullFlashTargetOpenOps)
}

func acquireExclusiveFullFlashTargetWithOps(
	ctx context.Context,
	sourceLease *FullFlashSourceLease,
	expectedPreflight FullFlashTargetPreflightPlan,
	ops fullFlashTargetOpenOps,
) (*FullFlashTargetSession, error) {
	if ctx == nil {
		return nil, errors.New("FFU target-acquisition context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sourceLease == nil {
		return nil, errors.New("FFU authenticated source lease is nil")
	}
	if err := validateFullFlashTargetPreflightPlan(expectedPreflight); err != nil {
		return nil, fmt.Errorf("validate expected FFU target preflight: %w", err)
	}
	if expectedPreflight.UnmountRequired || len(expectedPreflight.MountedTargets) != 0 {
		return nil, errors.New("FFU target must already be fully unmounted before exclusive acquisition")
	}
	if err := validateFullFlashTargetOpenOps(ops); err != nil {
		return nil, err
	}

	sourceLease.mu.Lock()
	defer sourceLease.mu.Unlock()
	if err := sourceLease.validateLocked(); err != nil {
		return nil, err
	}
	if err := sourceLease.lease.Context().Err(); err != nil {
		return nil, err
	}
	if err := sourceLease.lease.Check(); err != nil {
		return nil, err
	}
	if err := sourcefile.Verify(sourceLease.file, sourceLease.identity); err != nil {
		return nil, err
	}
	sourceEvidence := sourceLease.evidence
	if sourceEvidence.FullFlashTargetPreflightSHA256 != expectedPreflight.PlanSHA256 ||
		sourceEvidence.FullFlashValidationPlanSHA256 != expectedPreflight.FullFlashValidationPlanSHA256 ||
		sourceEvidence.RestoreTargetPlanSHA256 != expectedPreflight.RestoreTargetPlanSHA256 ||
		sourceEvidence.AuthenticatedIntegritySHA256 != expectedPreflight.AuthenticatedIntegritySHA256 ||
		sourceEvidence.TargetDevicePath != expectedPreflight.DevicePath ||
		sourceEvidence.ExpectedTargetIdentity != expectedPreflight.ExpectedTargetIdentity ||
		sourceEvidence.TargetSizeBytes != expectedPreflight.TargetSizeBytes {
		return nil, errors.New("FFU source lease does not bind the reviewed target preflight")
	}

	target, err := ops.openTarget(expectedPreflight.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("open exclusive FFU target: %w", err)
	}
	closeTarget := true
	defer func() {
		if closeTarget {
			_ = target.Close()
		}
	}()

	if err := ops.verifyOpenTarget(target, expectedPreflight.KernelDeviceID, expectedPreflight.TargetSizeBytes); err != nil {
		return nil, fmt.Errorf("verify opened FFU target: %w", err)
	}
	dev, kernelID, err := ops.revalidateTarget(expectedPreflight.DevicePath, expectedPreflight.KernelDeviceID)
	if err != nil {
		return nil, fmt.Errorf("revalidate opened FFU target: %w", err)
	}
	if err := validateAcquiredFullFlashTargetSnapshot(expectedPreflight, dev, kernelID, ops); err != nil {
		return nil, err
	}
	if err := ops.ensureSourceOutside(sourceLease.file, dev); err != nil {
		return nil, fmt.Errorf("confirm FFU source is outside the target: %w", err)
	}
	if err := sourceLease.lease.Check(); err != nil {
		return nil, err
	}
	if err := sourcefile.Verify(sourceLease.file, sourceLease.identity); err != nil {
		return nil, err
	}
	if err := ops.verifyOpenTarget(target, expectedPreflight.KernelDeviceID, expectedPreflight.TargetSizeBytes); err != nil {
		return nil, fmt.Errorf("reverify opened FFU target: %w", err)
	}

	evidence := FullFlashTargetSessionEvidence{
		Schema:                         fullFlashTargetSessionEvidenceSchema,
		Mode:                           "ffu-exclusive-target-session",
		SourceLeaseEvidenceSHA256:      sourceEvidence.PlanSHA256,
		FullFlashTargetPreflightSHA256: expectedPreflight.PlanSHA256,
		FullFlashValidationPlanSHA256:  expectedPreflight.FullFlashValidationPlanSHA256,
		RestoreTargetPlanSHA256:        expectedPreflight.RestoreTargetPlanSHA256,
		AuthenticatedIntegritySHA256:   expectedPreflight.AuthenticatedIntegritySHA256,
		DevicePath:                     expectedPreflight.DevicePath,
		ExpectedTargetIdentity:         expectedPreflight.ExpectedTargetIdentity,
		RediscoveredTargetIdentity:     device.IdentityToken(dev),
		TargetSizeBytes:                expectedPreflight.TargetSizeBytes,
		LogicalSectorSizeBytes:         expectedPreflight.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes:        expectedPreflight.PhysicalSectorSizeBytes,
		StoreBlockSizeBytes:            expectedPreflight.StoreBlockSizeBytes,
		ExpectedKernelDeviceID:         expectedPreflight.KernelDeviceID,
		ObservedKernelDeviceID:         kernelID,
		MajorMinor:                     dev.MajorMinor,
		MutationBytes:                  expectedPreflight.MutationBytes,
		SourceLeaseHeld:                true,
		TargetOpenedReadWrite:          true,
		KernelExclusiveOpen:            true,
		NoFollowOpen:                   true,
		MountedTargetsAbsent:           true,
		GuardedUnmountPerformed:        false,
		TargetDescriptorVerified:       true,
		TargetPolicyRevalidated:        true,
		TargetGeometryRevalidated:      true,
		SourceOutsideTargetConfirmed:   true,
		FixedDiskOverrideAllowed:       false,
		TargetAccessAcquired:           true,
		MutationPermitted:              false,
		ExecutionSupported:             false,
		Warnings:                       fullFlashTargetSessionWarnings(),
		Limitations:                    fullFlashTargetSessionLimitations(),
	}
	evidence.PlanSHA256 = fullFlashTargetSessionEvidenceDigest(evidence)
	if err := validateFullFlashTargetSessionEvidence(evidence); err != nil {
		return nil, err
	}

	session := &FullFlashTargetSession{
		file: target, source: sourceLease, preflight: expectedPreflight,
		evidence: evidence, ops: ops, seal: issuedFullFlashTargetSessionSeal,
	}
	closeTarget = false
	return session, nil
}

func validateAcquiredFullFlashTargetSnapshot(
	preflight FullFlashTargetPreflightPlan,
	dev device.BlockDevice,
	kernelID uint64,
	ops fullFlashTargetOpenOps,
) error {
	if kernelID == 0 || kernelID != preflight.KernelDeviceID {
		return errors.New("FFU target kernel identity changed during exclusive acquisition")
	}
	if dev.Path != preflight.DevicePath || dev.Type != "disk" || dev.ReadOnly || dev.Size != preflight.TargetSizeBytes {
		return errors.New("FFU target whole-disk metadata changed during exclusive acquisition")
	}
	if device.IdentityToken(dev) != preflight.ExpectedTargetIdentity {
		return errors.New("FFU target identity changed during exclusive acquisition")
	}
	mounts, err := collectFullFlashTargetMounts(dev)
	if err != nil {
		return err
	}
	if len(mounts) != 0 {
		return errors.New("FFU target became mounted during exclusive acquisition")
	}
	logical, physical, err := ops.readSectorGeometry(dev.Name)
	if err != nil {
		return err
	}
	if logical != preflight.LogicalSectorSizeBytes || physical != preflight.PhysicalSectorSizeBytes || preflight.StoreBlockSizeBytes%logical != 0 || preflight.StoreBlockSizeBytes%physical != 0 {
		return errors.New("FFU target sector geometry changed during exclusive acquisition")
	}
	return nil
}

func validateFullFlashTargetOpenOps(ops fullFlashTargetOpenOps) error {
	if ops.openTarget == nil || ops.verifyOpenTarget == nil || ops.revalidateTarget == nil || ops.readSectorGeometry == nil || ops.ensureSourceOutside == nil {
		return errors.New("FFU target-acquisition operations are incomplete")
	}
	return nil
}

// Evidence returns an independently owned copy of the target-session evidence.
func (session *FullFlashTargetSession) Evidence() (FullFlashTargetSessionEvidence, error) {
	if session == nil {
		return FullFlashTargetSessionEvidence{}, errors.New("FFU target session is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.validateLocked(); err != nil {
		return FullFlashTargetSessionEvidence{}, err
	}
	result := session.evidence
	result.Warnings = append([]string(nil), result.Warnings...)
	result.Limitations = append([]string(nil), result.Limitations...)
	return result, nil
}

// Check proves that the source lease and target descriptor remain healthy and
// that the live target policy, identity, capacity, mount state, and geometry
// still match the acquired session.
func (session *FullFlashTargetSession) Check() error {
	if session == nil {
		return errors.New("FFU target session is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.validateLocked(); err != nil {
		return err
	}
	if err := session.source.Check(); err != nil {
		return err
	}
	if err := session.ops.verifyOpenTarget(session.file, session.preflight.KernelDeviceID, session.preflight.TargetSizeBytes); err != nil {
		return err
	}
	dev, kernelID, err := session.ops.revalidateTarget(session.preflight.DevicePath, session.preflight.KernelDeviceID)
	if err != nil {
		return err
	}
	if err := validateAcquiredFullFlashTargetSnapshot(session.preflight, dev, kernelID, session.ops); err != nil {
		return err
	}
	session.source.mu.Lock()
	defer session.source.mu.Unlock()
	if err := session.source.validateLocked(); err != nil {
		return err
	}
	if err := session.source.lease.Check(); err != nil {
		return err
	}
	if err := sourcefile.Verify(session.source.file, session.source.identity); err != nil {
		return err
	}
	return session.ops.ensureSourceOutside(session.source.file, dev)
}

// Close releases the exclusive target descriptor. It deliberately does not
// release the caller-owned source lease.
func (session *FullFlashTargetSession) Close() error {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	if session.seal != issuedFullFlashTargetSessionSeal || session.file == nil {
		return errors.New("invalid FFU target-session capability")
	}
	session.closed = true
	return session.file.Close()
}

func (session *FullFlashTargetSession) validateLocked() error {
	if session.closed {
		return errors.New("FFU target session is closed")
	}
	if session.seal != issuedFullFlashTargetSessionSeal || session.file == nil || session.source == nil {
		return errors.New("invalid FFU target-session capability")
	}
	if err := validateFullFlashTargetOpenOps(session.ops); err != nil {
		return err
	}
	return validateFullFlashTargetSessionEvidence(session.evidence)
}

func validateFullFlashTargetSessionEvidence(evidence FullFlashTargetSessionEvidence) error {
	if evidence.Schema != fullFlashTargetSessionEvidenceSchema || evidence.Mode != "ffu-exclusive-target-session" || !evidence.SourceLeaseHeld || !evidence.TargetOpenedReadWrite || !evidence.KernelExclusiveOpen || !evidence.NoFollowOpen || !evidence.MountedTargetsAbsent || evidence.GuardedUnmountPerformed || !evidence.TargetDescriptorVerified || !evidence.TargetPolicyRevalidated || !evidence.TargetGeometryRevalidated || !evidence.SourceOutsideTargetConfirmed || evidence.FixedDiskOverrideAllowed || !evidence.TargetAccessAcquired || evidence.MutationPermitted || evidence.ExecutionSupported {
		return errors.New("invalid FFU target-session evidence envelope")
	}
	path := strings.TrimSpace(evidence.DevicePath)
	if path == "" || path != evidence.DevicePath || !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
		return errors.New("FFU target-session evidence contains an invalid target path")
	}
	for _, value := range []string{
		evidence.SourceLeaseEvidenceSHA256,
		evidence.FullFlashTargetPreflightSHA256,
		evidence.FullFlashValidationPlanSHA256,
		evidence.RestoreTargetPlanSHA256,
		evidence.AuthenticatedIntegritySHA256,
		evidence.ExpectedTargetIdentity,
		evidence.RediscoveredTargetIdentity,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU target-session evidence contains an invalid SHA-256 identifier")
		}
	}
	if evidence.ExpectedTargetIdentity != evidence.RediscoveredTargetIdentity || evidence.TargetSizeBytes == 0 || evidence.MutationBytes == 0 || evidence.MutationBytes > evidence.TargetSizeBytes || evidence.LogicalSectorSizeBytes == 0 || evidence.PhysicalSectorSizeBytes == 0 || evidence.StoreBlockSizeBytes == 0 || evidence.ExpectedKernelDeviceID == 0 || evidence.ExpectedKernelDeviceID != evidence.ObservedKernelDeviceID || strings.TrimSpace(evidence.MajorMinor) == "" {
		return errors.New("FFU target-session identity or geometry evidence is inconsistent")
	}
	if evidence.StoreBlockSizeBytes%evidence.LogicalSectorSizeBytes != 0 || evidence.StoreBlockSizeBytes%evidence.PhysicalSectorSizeBytes != 0 {
		return errors.New("FFU target-session sector binding is inconsistent")
	}
	if !equalRestoreStrings(evidence.Warnings, fullFlashTargetSessionWarnings()) || !equalRestoreStrings(evidence.Limitations, fullFlashTargetSessionLimitations()) || evidence.PlanSHA256 != fullFlashTargetSessionEvidenceDigest(evidence) {
		return errors.New("FFU target-session evidence, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashTargetSessionWarnings() []string {
	return []string{
		"The target is open read/write with Linux kernel exclusivity, but this capability exposes no mutation operation.",
		"The authenticated source lease and exclusive target descriptor must both remain healthy until final cleanup.",
		"A separate execution authorization and destructive transaction are still required before any byte may be written.",
	}
}

func fullFlashTargetSessionLimitations() []string {
	return []string{
		"targets that require unmounting remain unsupported by this acquisition boundary",
		"the target descriptor is package-private and cannot be extracted by callers",
		"guarded unmount, execution authorization, write ordering, cancellation reporting, flush, readback, and result publication remain outside this boundary",
		"mutation and execution remain disabled",
	}
}

func fullFlashTargetSessionEvidenceDigest(evidence FullFlashTargetSessionEvidence) string {
	digest := sha256.New()
	writeTargetSessionUint64(digest, uint64(evidence.Schema))
	writeTargetSessionString(digest, evidence.Mode)
	writeTargetSessionString(digest, evidence.SourceLeaseEvidenceSHA256)
	writeTargetSessionString(digest, evidence.FullFlashTargetPreflightSHA256)
	writeTargetSessionString(digest, evidence.FullFlashValidationPlanSHA256)
	writeTargetSessionString(digest, evidence.RestoreTargetPlanSHA256)
	writeTargetSessionString(digest, evidence.AuthenticatedIntegritySHA256)
	writeTargetSessionString(digest, evidence.DevicePath)
	writeTargetSessionString(digest, evidence.ExpectedTargetIdentity)
	writeTargetSessionString(digest, evidence.RediscoveredTargetIdentity)
	writeTargetSessionUint64(digest, evidence.TargetSizeBytes)
	writeTargetSessionUint64(digest, evidence.LogicalSectorSizeBytes)
	writeTargetSessionUint64(digest, evidence.PhysicalSectorSizeBytes)
	writeTargetSessionUint64(digest, evidence.StoreBlockSizeBytes)
	writeTargetSessionUint64(digest, evidence.ExpectedKernelDeviceID)
	writeTargetSessionUint64(digest, evidence.ObservedKernelDeviceID)
	writeTargetSessionString(digest, evidence.MajorMinor)
	writeTargetSessionUint64(digest, evidence.MutationBytes)
	writeTargetSessionBool(digest, evidence.SourceLeaseHeld)
	writeTargetSessionBool(digest, evidence.TargetOpenedReadWrite)
	writeTargetSessionBool(digest, evidence.KernelExclusiveOpen)
	writeTargetSessionBool(digest, evidence.NoFollowOpen)
	writeTargetSessionBool(digest, evidence.MountedTargetsAbsent)
	writeTargetSessionBool(digest, evidence.GuardedUnmountPerformed)
	writeTargetSessionBool(digest, evidence.TargetDescriptorVerified)
	writeTargetSessionBool(digest, evidence.TargetPolicyRevalidated)
	writeTargetSessionBool(digest, evidence.TargetGeometryRevalidated)
	writeTargetSessionBool(digest, evidence.SourceOutsideTargetConfirmed)
	writeTargetSessionBool(digest, evidence.FixedDiskOverrideAllowed)
	writeTargetSessionBool(digest, evidence.TargetAccessAcquired)
	writeTargetSessionBool(digest, evidence.MutationPermitted)
	writeTargetSessionBool(digest, evidence.ExecutionSupported)
	for _, warning := range evidence.Warnings {
		writeTargetSessionString(digest, warning)
	}
	for _, limitation := range evidence.Limitations {
		writeTargetSessionString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeTargetSessionUint64(digest hash.Hash, value uint64) { writeSourceLeaseUint64(digest, value) }
func writeTargetSessionString(digest hash.Hash, value string) { writeSourceLeaseString(digest, value) }
func writeTargetSessionBool(digest hash.Hash, value bool)     { writeSourceLeaseBool(digest, value) }
