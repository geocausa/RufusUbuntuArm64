//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	"os"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const (
	fullFlashExecutionResultSchema = 1
	defaultFullFlashChunkSize      = 4 * 1024 * 1024
)

const (
	fullFlashExecutionStatusNotStarted        = "not-started"
	fullFlashExecutionStatusPartiallyChanged  = "partially-modified"
	fullFlashExecutionStatusWrittenUnverified = "written-unverified"
	fullFlashExecutionStatusVerified          = "verified"
)

// FullFlashExecutionResult records the exact state reached by one attempted
// single-phase FFU transaction. It is returned on both success and failure so a
// caller never has to infer whether destructive mutation may have begun.
type FullFlashExecutionResult struct {
	Schema                        int      `json:"schema"`
	Mode                          string   `json:"mode"`
	Status                        string   `json:"status"`
	MutationAuthorizationSHA256   string   `json:"mutation_authorization_sha256"`
	ConfirmationEvidenceSHA256    string   `json:"confirmation_evidence_sha256"`
	TargetSessionEvidenceSHA256   string   `json:"target_session_evidence_sha256"`
	SourceLeaseEvidenceSHA256     string   `json:"source_lease_evidence_sha256"`
	WriteOrderPlanSHA256          string   `json:"write_order_plan_sha256"`
	FullFlashValidationPlanSHA256 string   `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256       string   `json:"restore_target_plan_sha256"`
	DescriptorPlanSHA256          string   `json:"descriptor_plan_sha256"`
	AuthenticatedIntegritySHA256  string   `json:"authenticated_integrity_sha256"`
	DevicePath                    string   `json:"device_path"`
	ExpectedTargetIdentity        string   `json:"expected_target_identity"`
	TargetSizeBytes               uint64   `json:"target_size_bytes"`
	OperationCountPlanned         uint64   `json:"operation_count_planned"`
	OperationCountCompleted       uint64   `json:"operation_count_completed"`
	MutationBytesPlanned          uint64   `json:"mutation_bytes_planned"`
	MutationBytesWritten          uint64   `json:"mutation_bytes_written"`
	AuthorizationConsumed         bool     `json:"authorization_consumed"`
	SourceLeaseRevalidated        bool     `json:"source_lease_revalidated"`
	TargetSessionRevalidated      bool     `json:"target_session_revalidated"`
	MutationStarted               bool     `json:"mutation_started"`
	WriteCompleted                bool     `json:"write_completed"`
	SyncCompleted                 bool     `json:"sync_completed"`
	ReadbackCompleted             bool     `json:"readback_completed"`
	CancellationObserved          bool     `json:"cancellation_observed"`
	CancelledBeforeMutation       bool     `json:"cancelled_before_mutation"`
	CancelledAfterMutation        bool     `json:"cancelled_after_mutation"`
	TargetMayBePartiallyModified  bool     `json:"target_may_be_partially_modified"`
	ExecutionSucceeded            bool     `json:"execution_succeeded"`
	ErrorObserved                 bool     `json:"error_observed"`
	ErrorStage                    string   `json:"error_stage"`
	ResultSHA256                  string   `json:"result_sha256"`
	Warnings                      []string `json:"warnings"`
	Limitations                   []string `json:"limitations"`
}

type fullFlashExecutionOps struct {
	chunkSize        int
	readSource       func(*os.File, []byte, int64) (int, error)
	writeTarget      func(*os.File, []byte, int64) (int, error)
	syncTarget       func(*os.File) error
	readTarget       func(*os.File, []byte, int64) (int, error)
	beforeFirstWrite func()
	afterWriteChunk  func(uint64)
}

func defaultFullFlashExecutionOps() fullFlashExecutionOps {
	return fullFlashExecutionOps{
		chunkSize:   defaultFullFlashChunkSize,
		readSource:  func(file *os.File, buffer []byte, offset int64) (int, error) { return file.ReadAt(buffer, offset) },
		writeTarget: func(file *os.File, buffer []byte, offset int64) (int, error) { return file.WriteAt(buffer, offset) },
		syncTarget:  func(file *os.File) error { return file.Sync() },
		readTarget:  func(file *os.File, buffer []byte, offset int64) (int, error) { return file.ReadAt(buffer, offset) },
	}
}

// ExecuteAuthorizedSinglePhaseFullFlash consumes one sealed mutation
// authorization and writes only its internally held declaration-order
// operations. It uses the already-held source and target descriptors, performs
// an fsync durability boundary, and reads every written extent back before
// reporting success.
func ExecuteAuthorizedSinglePhaseFullFlash(ctx context.Context, authorization *FullFlashMutationAuthorization) (FullFlashExecutionResult, error) {
	return executeAuthorizedSinglePhaseFullFlashWithOps(ctx, authorization, defaultFullFlashExecutionOps())
}

func executeAuthorizedSinglePhaseFullFlashWithOps(ctx context.Context, authorization *FullFlashMutationAuthorization, ops fullFlashExecutionOps) (result FullFlashExecutionResult, resultErr error) {
	if ctx == nil {
		return finalizeFullFlashExecutionFailure(result, "context", errors.New("FFU execution context is nil"))
	}
	if authorization == nil {
		return finalizeFullFlashExecutionFailure(result, "authorization", errors.New("FFU mutation authorization is nil"))
	}
	if err := validateFullFlashExecutionOps(ops); err != nil {
		return finalizeFullFlashExecutionFailure(result, "operations", err)
	}

	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	result = newFullFlashExecutionResult(authorization)
	if err := authorization.validateLocked(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "authorization", err)
	}
	if err := ctx.Err(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "preflight-context", err)
	}

	confirmation := authorization.confirmation
	confirmation.mu.Lock()
	defer confirmation.mu.Unlock()
	if err := confirmation.validateLocked(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "confirmation", err)
	}
	if confirmation.evidence.PlanSHA256 != authorization.evidence.ConfirmationEvidenceSHA256 || confirmation.evidence.TargetSessionEvidenceSHA256 != authorization.evidence.TargetSessionEvidenceSHA256 || confirmation.evidence.SourceLeaseEvidenceSHA256 != authorization.evidence.SourceLeaseEvidenceSHA256 || confirmation.evidence.FullFlashValidationPlanSHA256 != authorization.evidence.FullFlashValidationPlanSHA256 || confirmation.evidence.RestoreTargetPlanSHA256 != authorization.evidence.RestoreTargetPlanSHA256 || confirmation.evidence.AuthenticatedIntegritySHA256 != authorization.evidence.AuthenticatedIntegritySHA256 || confirmation.evidence.DevicePath != authorization.evidence.DevicePath || confirmation.evidence.ExpectedTargetIdentity != authorization.evidence.ExpectedTargetIdentity || confirmation.evidence.TargetSizeBytes != authorization.evidence.TargetSizeBytes || confirmation.evidence.MutationBytes != authorization.evidence.MutationBytes || confirmation.evidence.ExpectedConfirmationPhrase != authorization.evidence.ConfirmationPhrase {
		return finalizeFullFlashExecutionFailure(result, "confirmation-binding", errors.New("FFU confirmation no longer matches mutation authorization"))
	}

	target := confirmation.target
	target.mu.Lock()
	defer target.mu.Unlock()
	if err := target.validateLocked(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "target-session", err)
	}
	if target.evidence.PlanSHA256 != authorization.evidence.TargetSessionEvidenceSHA256 || target.evidence.SourceLeaseEvidenceSHA256 != authorization.evidence.SourceLeaseEvidenceSHA256 || target.evidence.FullFlashValidationPlanSHA256 != authorization.evidence.FullFlashValidationPlanSHA256 || target.evidence.RestoreTargetPlanSHA256 != authorization.evidence.RestoreTargetPlanSHA256 || target.evidence.AuthenticatedIntegritySHA256 != authorization.evidence.AuthenticatedIntegritySHA256 || target.evidence.DevicePath != authorization.evidence.DevicePath || target.evidence.ExpectedTargetIdentity != authorization.evidence.ExpectedTargetIdentity || target.evidence.TargetSizeBytes != authorization.evidence.TargetSizeBytes || target.evidence.MutationBytes != authorization.evidence.MutationBytes {
		return finalizeFullFlashExecutionFailure(result, "target-binding", errors.New("FFU target session no longer matches mutation authorization"))
	}

	source := target.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := source.validateLocked(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "source-lease", err)
	}
	if source.evidence.PlanSHA256 != authorization.evidence.SourceLeaseEvidenceSHA256 || source.evidence.FullFlashValidationPlanSHA256 != authorization.evidence.FullFlashValidationPlanSHA256 || source.evidence.RestoreTargetPlanSHA256 != authorization.evidence.RestoreTargetPlanSHA256 || source.evidence.AuthenticatedIntegritySHA256 != authorization.evidence.AuthenticatedIntegritySHA256 || source.evidence.TargetDevicePath != authorization.evidence.DevicePath || source.evidence.ExpectedTargetIdentity != authorization.evidence.ExpectedTargetIdentity || source.evidence.TargetSizeBytes != authorization.evidence.TargetSizeBytes {
		return finalizeFullFlashExecutionFailure(result, "source-binding", errors.New("FFU source lease no longer matches mutation authorization"))
	}
	if err := revalidateFullFlashExecutionLocked(target, source); err != nil {
		return finalizeFullFlashExecutionFailure(result, "live-revalidation", err)
	}
	result.SourceLeaseRevalidated = true
	result.TargetSessionRevalidated = true
	if err := ctx.Err(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "pre-mutation-context", err)
	}
	if leaseErr := source.lease.Context().Err(); leaseErr != nil {
		if err := source.lease.Check(); err != nil {
			leaseErr = err
		}
		return finalizeFullFlashExecutionFailure(result, "pre-mutation-source-lease", leaseErr)
	}
	if ops.beforeFirstWrite != nil {
		ops.beforeFirstWrite()
	}
	if err := ctx.Err(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "pre-first-write-context", err)
	}
	if err := source.lease.Check(); err != nil {
		return finalizeFullFlashExecutionFailure(result, "pre-first-write-source-lease", err)
	}
	if err := sourcefile.Verify(source.file, source.identity); err != nil {
		return finalizeFullFlashExecutionFailure(result, "pre-first-write-source-identity", err)
	}

	// Consumption is package-private and one-shot. It occurs immediately before
	// the first possible target write, after every live check has passed.
	authorization.consumed = true
	result.AuthorizationConsumed = true
	buffer := make([]byte, ops.chunkSize)
	for _, operation := range authorization.writeOrder.Operations {
		remaining := operation.PayloadLength
		sourceOffset := operation.PayloadOffset
		targetOffset := operation.TargetOffset
		for remaining > 0 {
			if err := ctx.Err(); err != nil {
				return finalizeFullFlashExecutionFailure(result, "write-context", err)
			}
			if err := source.lease.Check(); err != nil {
				return finalizeFullFlashExecutionFailure(result, "write-source-lease", err)
			}
			chunk := uint64(len(buffer))
			if chunk > remaining {
				chunk = remaining
			}
			sourcePosition, err := fullFlashExecutionOffset(sourceOffset)
			if err != nil {
				return finalizeFullFlashExecutionFailure(result, "source-offset", err)
			}
			targetPosition, err := fullFlashExecutionOffset(targetOffset)
			if err != nil {
				return finalizeFullFlashExecutionFailure(result, "target-offset", err)
			}
			payload := buffer[:int(chunk)]
			if err := readFullFlashAt(ops.readSource, source.file, payload, sourcePosition); err != nil {
				return finalizeFullFlashExecutionFailure(result, "source-read", err)
			}
			written, err := writeFullFlashAt(ops.writeTarget, target.file, payload, targetPosition)
			if written > 0 {
				result.MutationStarted = true
				result.MutationBytesWritten += uint64(written)
			}
			if ops.afterWriteChunk != nil && written > 0 {
				ops.afterWriteChunk(result.MutationBytesWritten)
			}
			if err != nil {
				return finalizeFullFlashExecutionFailure(result, "target-write", err)
			}
			if uint64(written) != chunk {
				return finalizeFullFlashExecutionFailure(result, "target-write", io.ErrShortWrite)
			}
			remaining -= chunk
			sourceOffset += chunk
			targetOffset += chunk
		}
		result.OperationCountCompleted++
	}
	if result.OperationCountCompleted != result.OperationCountPlanned || result.MutationBytesWritten != result.MutationBytesPlanned {
		return finalizeFullFlashExecutionFailure(result, "write-accounting", errors.New("FFU execution completed with inconsistent operation or byte accounting"))
	}
	result.WriteCompleted = true
	if err := ops.syncTarget(target.file); err != nil {
		return finalizeFullFlashExecutionFailure(result, "target-sync", err)
	}
	result.SyncCompleted = true
	if err := revalidateFullFlashExecutionLocked(target, source); err != nil {
		return finalizeFullFlashExecutionFailure(result, "post-write-revalidation", err)
	}

	sourceBuffer := make([]byte, ops.chunkSize)
	targetBuffer := make([]byte, ops.chunkSize)
	for _, operation := range authorization.writeOrder.Operations {
		remaining := operation.PayloadLength
		sourceOffset := operation.PayloadOffset
		targetOffset := operation.TargetOffset
		for remaining > 0 {
			if err := ctx.Err(); err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-context", err)
			}
			if err := source.lease.Check(); err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-source-lease", err)
			}
			chunk := uint64(len(sourceBuffer))
			if chunk > remaining {
				chunk = remaining
			}
			sourcePosition, err := fullFlashExecutionOffset(sourceOffset)
			if err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-source-offset", err)
			}
			targetPosition, err := fullFlashExecutionOffset(targetOffset)
			if err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-target-offset", err)
			}
			expected := sourceBuffer[:int(chunk)]
			actual := targetBuffer[:int(chunk)]
			if err := readFullFlashAt(ops.readSource, source.file, expected, sourcePosition); err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-source-read", err)
			}
			if err := readFullFlashAt(ops.readTarget, target.file, actual, targetPosition); err != nil {
				return finalizeFullFlashExecutionFailure(result, "readback-target-read", err)
			}
			if !bytes.Equal(expected, actual) {
				return finalizeFullFlashExecutionFailure(result, "readback-mismatch", errors.New("FFU target readback does not match the authenticated source payload"))
			}
			remaining -= chunk
			sourceOffset += chunk
			targetOffset += chunk
		}
	}
	if err := revalidateFullFlashExecutionLocked(target, source); err != nil {
		return finalizeFullFlashExecutionFailure(result, "final-revalidation", err)
	}
	result.ReadbackCompleted = true
	result.Status = fullFlashExecutionStatusVerified
	result.ExecutionSucceeded = true
	result.ErrorObserved = false
	result.ErrorStage = ""
	result.TargetMayBePartiallyModified = false
	result.ResultSHA256 = fullFlashExecutionResultDigest(result)
	if err := validateFullFlashExecutionResult(result); err != nil {
		return result, err
	}
	return result, nil
}

func revalidateFullFlashExecutionLocked(target *FullFlashTargetSession, source *FullFlashSourceLease) error {
	if err := target.validateLocked(); err != nil {
		return err
	}
	if err := source.validateLocked(); err != nil {
		return err
	}
	if err := source.lease.Check(); err != nil {
		return err
	}
	if err := sourcefile.Verify(source.file, source.identity); err != nil {
		return err
	}
	if err := target.ops.verifyOpenTarget(target.file, target.preflight.KernelDeviceID, target.preflight.TargetSizeBytes); err != nil {
		return err
	}
	dev, kernelID, err := target.ops.revalidateTarget(target.preflight.DevicePath, target.preflight.KernelDeviceID)
	if err != nil {
		return err
	}
	if err := validateAcquiredFullFlashTargetSnapshot(target.preflight, dev, kernelID, target.ops); err != nil {
		return err
	}
	return target.ops.ensureSourceOutside(source.file, dev)
}

func validateFullFlashExecutionOps(ops fullFlashExecutionOps) error {
	if ops.chunkSize <= 0 || ops.chunkSize > 64*1024*1024 || ops.readSource == nil || ops.writeTarget == nil || ops.syncTarget == nil || ops.readTarget == nil {
		return errors.New("FFU execution operations are incomplete or invalid")
	}
	return nil
}

func fullFlashExecutionOffset(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, errors.New("FFU execution byte offset exceeds Linux signed offset range")
	}
	return int64(value), nil
}

func readFullFlashAt(read func(*os.File, []byte, int64) (int, error), file *os.File, buffer []byte, offset int64) error {
	for len(buffer) > 0 {
		n, err := read(file, buffer, offset)
		if n > 0 {
			buffer = buffer[n:]
			offset += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buffer) == 0 {
				return nil
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeFullFlashAt(write func(*os.File, []byte, int64) (int, error), file *os.File, buffer []byte, offset int64) (int, error) {
	total := 0
	for len(buffer) > 0 {
		n, err := write(file, buffer, offset)
		if n > 0 {
			total += n
			buffer = buffer[n:]
			offset += int64(n)
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func newFullFlashExecutionResult(authorization *FullFlashMutationAuthorization) FullFlashExecutionResult {
	evidence := authorization.evidence
	order := authorization.writeOrder
	return FullFlashExecutionResult{
		Schema:                        fullFlashExecutionResultSchema,
		Mode:                          "ffu-single-phase-execution",
		Status:                        fullFlashExecutionStatusNotStarted,
		MutationAuthorizationSHA256:   evidence.PlanSHA256,
		ConfirmationEvidenceSHA256:    evidence.ConfirmationEvidenceSHA256,
		TargetSessionEvidenceSHA256:   evidence.TargetSessionEvidenceSHA256,
		SourceLeaseEvidenceSHA256:     evidence.SourceLeaseEvidenceSHA256,
		WriteOrderPlanSHA256:          order.PlanSHA256,
		FullFlashValidationPlanSHA256: evidence.FullFlashValidationPlanSHA256,
		RestoreTargetPlanSHA256:       evidence.RestoreTargetPlanSHA256,
		DescriptorPlanSHA256:          evidence.DescriptorPlanSHA256,
		AuthenticatedIntegritySHA256:  evidence.AuthenticatedIntegritySHA256,
		DevicePath:                    evidence.DevicePath,
		ExpectedTargetIdentity:        evidence.ExpectedTargetIdentity,
		TargetSizeBytes:               evidence.TargetSizeBytes,
		OperationCountPlanned:         order.OperationCount,
		MutationBytesPlanned:          order.MutationBytes,
		AuthorizationConsumed:         authorization.consumed,
		Warnings:                      fullFlashExecutionWarnings(),
		Limitations:                   fullFlashExecutionLimitations(),
	}
}

func finalizeFullFlashExecutionFailure(result FullFlashExecutionResult, stage string, err error) (FullFlashExecutionResult, error) {
	result.ExecutionSucceeded = false
	result.ErrorObserved = true
	result.ErrorStage = stage
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		result.CancellationObserved = true
		if result.MutationStarted {
			result.CancelledAfterMutation = true
		} else {
			result.CancelledBeforeMutation = true
		}
	}
	switch {
	case !result.MutationStarted:
		result.Status = fullFlashExecutionStatusNotStarted
		result.TargetMayBePartiallyModified = false
	case result.WriteCompleted && result.SyncCompleted:
		result.Status = fullFlashExecutionStatusWrittenUnverified
		result.TargetMayBePartiallyModified = true
	default:
		result.Status = fullFlashExecutionStatusPartiallyChanged
		result.TargetMayBePartiallyModified = true
	}
	result.ResultSHA256 = fullFlashExecutionResultDigest(result)
	return result, err
}

func validateFullFlashExecutionResult(result FullFlashExecutionResult) error {
	if result.Schema != fullFlashExecutionResultSchema || result.Mode != "ffu-single-phase-execution" || result.Status != fullFlashExecutionStatusVerified || !result.AuthorizationConsumed || !result.SourceLeaseRevalidated || !result.TargetSessionRevalidated || !result.MutationStarted || !result.WriteCompleted || !result.SyncCompleted || !result.ReadbackCompleted || result.CancellationObserved || result.CancelledBeforeMutation || result.CancelledAfterMutation || result.TargetMayBePartiallyModified || !result.ExecutionSucceeded || result.ErrorObserved || result.ErrorStage != "" {
		return errors.New("invalid successful FFU execution result envelope")
	}
	for _, value := range []string{
		result.MutationAuthorizationSHA256,
		result.ConfirmationEvidenceSHA256,
		result.TargetSessionEvidenceSHA256,
		result.SourceLeaseEvidenceSHA256,
		result.WriteOrderPlanSHA256,
		result.FullFlashValidationPlanSHA256,
		result.RestoreTargetPlanSHA256,
		result.DescriptorPlanSHA256,
		result.AuthenticatedIntegritySHA256,
		result.ExpectedTargetIdentity,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("successful FFU execution result contains an invalid SHA-256 identifier")
		}
	}
	if result.DevicePath == "" || result.TargetSizeBytes == 0 || result.OperationCountPlanned == 0 || result.OperationCountCompleted != result.OperationCountPlanned || result.MutationBytesPlanned == 0 || result.MutationBytesWritten != result.MutationBytesPlanned || result.MutationBytesWritten > result.TargetSizeBytes || !equalRestoreStrings(result.Warnings, fullFlashExecutionWarnings()) || !equalRestoreStrings(result.Limitations, fullFlashExecutionLimitations()) || result.ResultSHA256 != fullFlashExecutionResultDigest(result) {
		return errors.New("successful FFU execution result accounting or evidence was altered")
	}
	return nil
}

func fullFlashExecutionWarnings() []string {
	return []string{
		"This transaction destructively writes the exact confirmed target using only the sealed single-phase operation plan.",
		"Cancellation or failure after mutation begins may leave the target partially modified; the result reports that state explicitly.",
		"Success is reported only after target synchronization, complete extent readback, and final source and target revalidation.",
		"Software restoration cannot prove physical bootability or complete device health.",
	}
}

func fullFlashExecutionLimitations() []string {
	return []string{
		"only the non-staged single-phase FFU profile is executable",
		"the executor uses already-held package-private descriptors and performs no path reopen, unmount, or privilege operation",
		"the sealed authorization is one-shot and cannot be reused after execution begins",
		"provider integration, administrator authentication, GTK exposure, real signed FFU evidence, and physical boot qualification remain separate gates",
	}
}

func fullFlashExecutionResultDigest(result FullFlashExecutionResult) string {
	digest := sha256.New()
	writeExecutionUint64(digest, uint64(result.Schema))
	writeExecutionString(digest, result.Mode)
	writeExecutionString(digest, result.Status)
	writeExecutionString(digest, result.MutationAuthorizationSHA256)
	writeExecutionString(digest, result.ConfirmationEvidenceSHA256)
	writeExecutionString(digest, result.TargetSessionEvidenceSHA256)
	writeExecutionString(digest, result.SourceLeaseEvidenceSHA256)
	writeExecutionString(digest, result.WriteOrderPlanSHA256)
	writeExecutionString(digest, result.FullFlashValidationPlanSHA256)
	writeExecutionString(digest, result.RestoreTargetPlanSHA256)
	writeExecutionString(digest, result.DescriptorPlanSHA256)
	writeExecutionString(digest, result.AuthenticatedIntegritySHA256)
	writeExecutionString(digest, result.DevicePath)
	writeExecutionString(digest, result.ExpectedTargetIdentity)
	writeExecutionUint64(digest, result.TargetSizeBytes)
	writeExecutionUint64(digest, result.OperationCountPlanned)
	writeExecutionUint64(digest, result.OperationCountCompleted)
	writeExecutionUint64(digest, result.MutationBytesPlanned)
	writeExecutionUint64(digest, result.MutationBytesWritten)
	writeExecutionBool(digest, result.AuthorizationConsumed)
	writeExecutionBool(digest, result.SourceLeaseRevalidated)
	writeExecutionBool(digest, result.TargetSessionRevalidated)
	writeExecutionBool(digest, result.MutationStarted)
	writeExecutionBool(digest, result.WriteCompleted)
	writeExecutionBool(digest, result.SyncCompleted)
	writeExecutionBool(digest, result.ReadbackCompleted)
	writeExecutionBool(digest, result.CancellationObserved)
	writeExecutionBool(digest, result.CancelledBeforeMutation)
	writeExecutionBool(digest, result.CancelledAfterMutation)
	writeExecutionBool(digest, result.TargetMayBePartiallyModified)
	writeExecutionBool(digest, result.ExecutionSucceeded)
	writeExecutionBool(digest, result.ErrorObserved)
	writeExecutionString(digest, result.ErrorStage)
	for _, warning := range result.Warnings {
		writeExecutionString(digest, warning)
	}
	for _, limitation := range result.Limitations {
		writeExecutionString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeExecutionUint64(digest hash.Hash, value uint64) {
	writeMutationAuthorizationUint64(digest, value)
}

func writeExecutionString(digest hash.Hash, value string) {
	writeMutationAuthorizationString(digest, value)
}

func writeExecutionBool(digest hash.Hash, value bool) {
	writeMutationAuthorizationBool(digest, value)
}
