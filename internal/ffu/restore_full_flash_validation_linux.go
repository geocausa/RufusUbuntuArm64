//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

const (
	fullFlashValidationPlanSchema = 1
	fullFlashUpdateType           = uint32(0)
)

// FullFlashValidationPlan records the fail-closed decision that one already
// authenticated, target-bound FFU is a complete full-flash image and therefore
// requires no partial-update validation descriptors. It grants no authority to
// open or modify the target.
type FullFlashValidationPlan struct {
	Schema                           int      `json:"schema"`
	Mode                             string   `json:"mode"`
	Destructive                      bool     `json:"destructive"`
	SourceFileSize                   uint64   `json:"source_file_size"`
	RestoreTargetPlanSHA256          string   `json:"restore_target_plan_sha256"`
	AuthenticatedIntegrityPlanSHA256 string   `json:"authenticated_integrity_plan_sha256"`
	DescriptorPlanSHA256             string   `json:"descriptor_plan_sha256"`
	CatalogSHA256                    string   `json:"catalog_sha256"`
	HashTableSHA256                  string   `json:"hash_table_sha256"`
	DevicePath                       string   `json:"device_path"`
	ExpectedTargetIdentity           string   `json:"expected_target_identity"`
	TargetSizeBytes                  uint64   `json:"target_size_bytes"`
	LogicalSectorSizeBytes           uint64   `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes          uint64   `json:"physical_sector_size_bytes"`
	StoreBlockSizeBytes              uint64   `json:"store_block_size_bytes"`
	TargetBlockCount                 uint64   `json:"target_block_count"`
	MutationBytes                    uint64   `json:"mutation_bytes"`
	StoreUpdateType                  uint32   `json:"store_update_type"`
	ValidationDescriptorCount        uint64   `json:"validation_descriptor_count"`
	FullFlashUpdateConfirmed         bool     `json:"full_flash_update_confirmed"`
	ValidationDescriptorsAbsent      bool     `json:"validation_descriptors_absent"`
	ValidationChecksResolved         bool     `json:"validation_checks_resolved"`
	ConfirmationRequired             bool     `json:"confirmation_required"`
	ConfirmationPhrase               string   `json:"confirmation_phrase"`
	ExecutionSupported               bool     `json:"execution_supported"`
	PlanSHA256                       string   `json:"plan_sha256"`
	Warnings                         []string `json:"warnings"`
	Limitations                      []string `json:"limitations"`
}

// ResolveAuthenticatedSingleStoreV1FullFlash re-runs the complete source and
// target planning chain, then accepts only Microsoft's full-flash update type 0
// with no validation descriptors. Microsoft defines validation entries as a
// prerequisite for partial updates; partial and unknown update types remain a
// hard refusal for the initial provider.
//
// The function performs no target discovery, open, read, write, flush, or
// readback and always leaves execution disabled.
func ResolveAuthenticatedSingleStoreV1FullFlash(
	ctx context.Context,
	reader io.ReaderAt,
	sourceSize uint64,
	activation TrustBundleActivation,
	evaluationTime time.Time,
	sourcePolicy CatalogPublisherPolicy,
	request RestoreTargetRequest,
) (RestoreTargetPlan, FullFlashValidationPlan, error) {
	if ctx == nil {
		return RestoreTargetPlan{}, FullFlashValidationPlan{}, errors.New("FFU full-flash validation context is nil")
	}
	if err := ctx.Err(); err != nil {
		return RestoreTargetPlan{}, FullFlashValidationPlan{}, err
	}

	inspection, descriptor, _, _, _, integrity, target, err := BindAuthenticatedSingleStoreV1Target(
		ctx, reader, sourceSize, activation, evaluationTime, sourcePolicy, request,
	)
	if err != nil {
		return target, FullFlashValidationPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return target, FullFlashValidationPlan{}, err
	}
	if err := validateRestoreTargetPlan(target); err != nil {
		return target, FullFlashValidationPlan{}, fmt.Errorf("validate prerequisite FFU target plan: %w", err)
	}

	switch inspection.Store.UpdateType {
	case fullFlashUpdateType:
		// Continue below.
	case 1:
		return target, FullFlashValidationPlan{}, errors.New("partial FFU update type 1 is unsupported: the initial restore provider accepts complete full-flash images only")
	default:
		return target, FullFlashValidationPlan{}, fmt.Errorf("unsupported FFU update type %d: the initial restore provider accepts full-flash type 0 only", inspection.Store.UpdateType)
	}
	if inspection.Store.ValidateDescriptorCount != 0 || inspection.Store.ValidateDescriptorLength != 0 || len(descriptor.ValidationDescriptors) != 0 || target.ValidationDescriptorCount != 0 || target.ValidationChecksRequired {
		return target, FullFlashValidationPlan{}, errors.New("full-flash FFU contains validation descriptors reserved for partial updates")
	}
	if target.ValidationChecksResolved {
		return target, FullFlashValidationPlan{}, errors.New("prerequisite FFU target plan crossed the full-flash validation boundary")
	}

	phrase, err := RestoreTargetConfirmationPhrase(target)
	if err != nil {
		return target, FullFlashValidationPlan{}, err
	}
	plan := FullFlashValidationPlan{
		Schema:                           fullFlashValidationPlanSchema,
		Mode:                             "ffu-full-flash-restore",
		Destructive:                      true,
		SourceFileSize:                   sourceSize,
		RestoreTargetPlanSHA256:          target.PlanSHA256,
		AuthenticatedIntegrityPlanSHA256: integrity.PlanSHA256,
		DescriptorPlanSHA256:             descriptor.PlanSHA256,
		CatalogSHA256:                    integrity.CatalogSHA256,
		HashTableSHA256:                  integrity.HashTableSHA256,
		DevicePath:                       target.DevicePath,
		ExpectedTargetIdentity:           target.ExpectedTargetIdentity,
		TargetSizeBytes:                  target.TargetSizeBytes,
		LogicalSectorSizeBytes:           target.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes:          target.PhysicalSectorSizeBytes,
		StoreBlockSizeBytes:              target.StoreBlockSizeBytes,
		TargetBlockCount:                 target.TargetBlockCount,
		MutationBytes:                    target.MutationBytes,
		StoreUpdateType:                  inspection.Store.UpdateType,
		ValidationDescriptorCount:        0,
		FullFlashUpdateConfirmed:         true,
		ValidationDescriptorsAbsent:      true,
		ValidationChecksResolved:         true,
		ConfirmationRequired:             true,
		ConfirmationPhrase:               phrase,
		ExecutionSupported:               false,
		Warnings:                         fullFlashValidationWarnings(),
		Limitations:                      fullFlashValidationLimitations(),
	}
	plan.PlanSHA256 = fullFlashValidationPlanDigest(plan)
	if err := validateFullFlashValidationPlan(plan); err != nil {
		return target, FullFlashValidationPlan{}, err
	}
	return target, plan, nil
}

// FullFlashValidationConfirmationPhrase returns the exact destructive phrase
// bound into an already validated full-flash plan. It does not authorize or
// execute restoration.
func FullFlashValidationConfirmationPhrase(plan FullFlashValidationPlan) (string, error) {
	if err := validateFullFlashValidationPlan(plan); err != nil {
		return "", err
	}
	return plan.ConfirmationPhrase, nil
}

func validateFullFlashValidationPlan(plan FullFlashValidationPlan) error {
	if plan.Schema != fullFlashValidationPlanSchema || plan.Mode != "ffu-full-flash-restore" || !plan.Destructive || !plan.FullFlashUpdateConfirmed || !plan.ValidationDescriptorsAbsent || !plan.ValidationChecksResolved || !plan.ConfirmationRequired || plan.ExecutionSupported {
		return errors.New("invalid FFU full-flash validation-plan envelope")
	}
	request := RestoreTargetRequest{
		DevicePath:              plan.DevicePath,
		ExpectedTargetIdentity:  plan.ExpectedTargetIdentity,
		TargetSizeBytes:         plan.TargetSizeBytes,
		LogicalSectorSizeBytes:  plan.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes: plan.PhysicalSectorSizeBytes,
	}
	if _, err := validateRestoreTargetRequest(request); err != nil {
		return err
	}
	if plan.SourceFileSize == 0 || plan.StoreUpdateType != fullFlashUpdateType || plan.ValidationDescriptorCount != 0 || plan.StoreBlockSizeBytes == 0 || plan.TargetSizeBytes%plan.StoreBlockSizeBytes != 0 || plan.TargetBlockCount != plan.TargetSizeBytes/plan.StoreBlockSizeBytes || plan.MutationBytes == 0 || plan.MutationBytes > plan.TargetSizeBytes {
		return errors.New("FFU full-flash validation-plan geometry or update classification is inconsistent")
	}
	if plan.StoreBlockSizeBytes%plan.LogicalSectorSizeBytes != 0 || plan.StoreBlockSizeBytes%plan.PhysicalSectorSizeBytes != 0 {
		return errors.New("FFU full-flash validation-plan sector binding is inconsistent")
	}
	for _, value := range []string{
		plan.RestoreTargetPlanSHA256,
		plan.AuthenticatedIntegrityPlanSHA256,
		plan.DescriptorPlanSHA256,
		plan.CatalogSHA256,
		plan.HashTableSHA256,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU full-flash validation-plan contains an invalid SHA-256 evidence identifier")
		}
	}
	expectedPhrase := fmt.Sprintf("RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES", plan.DevicePath, plan.TargetSizeBytes)
	if plan.ConfirmationPhrase != expectedPhrase {
		return errors.New("FFU full-flash validation-plan confirmation phrase was altered")
	}
	if !equalRestoreStrings(plan.Warnings, fullFlashValidationWarnings()) || !equalRestoreStrings(plan.Limitations, fullFlashValidationLimitations()) || plan.PlanSHA256 != fullFlashValidationPlanDigest(plan) {
		return errors.New("FFU full-flash validation-plan evidence, warnings, or limitations were altered")
	}
	return nil
}

func validFullFlashPlanSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func fullFlashValidationWarnings() []string {
	return []string{
		"Restoring a full-flash FFU is destructive and can replace partition tables and data across the selected target.",
		"The exact source evidence and target identity, capacity, and sector geometry must be revalidated immediately before any future write.",
		"Partial FFU updates and every image containing validation descriptors are unsupported and must not be approximated as full restoration.",
		"Software authentication and restoration cannot prove that the resulting device will boot or that the complete device is healthy.",
	}
}

func fullFlashValidationLimitations() []string {
	return []string{
		"this plan resolves only update type 0 with zero validation descriptors",
		"the plan opens no target and performs no validation read or mutation",
		"mounted-target, running-system-disk, authorization, cancellation, write ordering, flush, readback, and changed-media policy remain outside this boundary",
		"execution remains disabled until a separately reviewed privileged provider is qualified",
	}
}

func fullFlashValidationPlanDigest(plan FullFlashValidationPlan) string {
	digest := sha256.New()
	writeFullFlashUint64(digest, uint64(plan.Schema))
	writeFullFlashString(digest, plan.Mode)
	writeFullFlashBool(digest, plan.Destructive)
	writeFullFlashUint64(digest, plan.SourceFileSize)
	writeFullFlashString(digest, plan.RestoreTargetPlanSHA256)
	writeFullFlashString(digest, plan.AuthenticatedIntegrityPlanSHA256)
	writeFullFlashString(digest, plan.DescriptorPlanSHA256)
	writeFullFlashString(digest, plan.CatalogSHA256)
	writeFullFlashString(digest, plan.HashTableSHA256)
	writeFullFlashString(digest, plan.DevicePath)
	writeFullFlashString(digest, plan.ExpectedTargetIdentity)
	writeFullFlashUint64(digest, plan.TargetSizeBytes)
	writeFullFlashUint64(digest, plan.LogicalSectorSizeBytes)
	writeFullFlashUint64(digest, plan.PhysicalSectorSizeBytes)
	writeFullFlashUint64(digest, plan.StoreBlockSizeBytes)
	writeFullFlashUint64(digest, plan.TargetBlockCount)
	writeFullFlashUint64(digest, plan.MutationBytes)
	writeFullFlashUint64(digest, uint64(plan.StoreUpdateType))
	writeFullFlashUint64(digest, plan.ValidationDescriptorCount)
	writeFullFlashBool(digest, plan.FullFlashUpdateConfirmed)
	writeFullFlashBool(digest, plan.ValidationDescriptorsAbsent)
	writeFullFlashBool(digest, plan.ValidationChecksResolved)
	writeFullFlashBool(digest, plan.ConfirmationRequired)
	writeFullFlashString(digest, plan.ConfirmationPhrase)
	writeFullFlashBool(digest, plan.ExecutionSupported)
	for _, warning := range plan.Warnings {
		writeFullFlashString(digest, warning)
	}
	for _, limitation := range plan.Limitations {
		writeFullFlashString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeFullFlashUint64(digest hash.Hash, value uint64) { writeRestoreUint64(digest, value) }
func writeFullFlashString(digest hash.Hash, value string) { writeRestoreString(digest, value) }
func writeFullFlashBool(digest hash.Hash, value bool)     { writeRestoreBool(digest, value) }
