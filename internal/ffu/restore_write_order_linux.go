//go:build linux

package ffu

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

const fullFlashWriteOrderPlanSchema = 1

// OrderedFullFlashWriteOperation binds one declared FFU payload descriptor and
// location to its exact source and target byte ranges. It is review evidence,
// not an operation that can access or modify a target.
type OrderedFullFlashWriteOperation struct {
	Sequence         uint64 `json:"sequence"`
	DescriptorIndex  uint32 `json:"descriptor_index"`
	LocationIndex    uint32 `json:"location_index"`
	Anchor           string `json:"anchor"`
	TargetStartBlock uint64 `json:"target_start_block"`
	TargetEndBlock   uint64 `json:"target_end_block"`
	TargetOffset     uint64 `json:"target_offset"`
	TargetLength     uint64 `json:"target_length"`
	PayloadOffset    uint64 `json:"payload_offset"`
	PayloadLength    uint64 `json:"payload_length"`
}

// FullFlashWriteOrderPlan records the only currently unambiguous write-order
// profile: no special initial or flash-only GPT payload ranges and one final
// table range covering the complete sequential payload. It preserves descriptor
// declaration order and grants no mutation or execution authority.
type FullFlashWriteOrderPlan struct {
	Schema                           int                              `json:"schema"`
	Mode                             string                           `json:"mode"`
	Destructive                      bool                             `json:"destructive"`
	DescriptorPlanSHA256             string                           `json:"descriptor_plan_sha256"`
	RestoreTargetPlanSHA256          string                           `json:"restore_target_plan_sha256"`
	FullFlashValidationPlanSHA256    string                           `json:"full_flash_validation_plan_sha256"`
	AuthenticatedIntegrityPlanSHA256 string                           `json:"authenticated_integrity_plan_sha256"`
	CatalogSHA256                    string                           `json:"catalog_sha256"`
	HashTableSHA256                  string                           `json:"hash_table_sha256"`
	SourceFileSize                   uint64                           `json:"source_file_size"`
	DevicePath                       string                           `json:"device_path"`
	ExpectedTargetIdentity           string                           `json:"expected_target_identity"`
	TargetSizeBytes                  uint64                           `json:"target_size_bytes"`
	StoreBlockSizeBytes              uint64                           `json:"store_block_size_bytes"`
	TargetBlockCount                 uint64                           `json:"target_block_count"`
	PayloadOffset                    uint64                           `json:"payload_offset"`
	PayloadLength                    uint64                           `json:"payload_length"`
	PayloadEnd                       uint64                           `json:"payload_end"`
	TotalPayloadBlocks               uint64                           `json:"total_payload_blocks"`
	InitialTable                     PayloadTableRange                `json:"initial_table"`
	FlashOnlyTable                   PayloadTableRange                `json:"flash_only_table"`
	FinalTable                       PayloadTableRange                `json:"final_table"`
	WriteDescriptorCount             uint64                           `json:"write_descriptor_count"`
	OperationCount                   uint64                           `json:"operation_count"`
	MutationBytes                    uint64                           `json:"mutation_bytes"`
	SinglePhasePayloadProfile        bool                             `json:"single_phase_payload_profile"`
	SpecialGPTPhasesAbsent           bool                             `json:"special_gpt_phases_absent"`
	FinalTableCoversPayload          bool                             `json:"final_table_covers_payload"`
	DeclaredDescriptorOrderPreserved bool                             `json:"declared_descriptor_order_preserved"`
	ConfirmationPhrase               string                           `json:"confirmation_phrase"`
	ConfirmationStillRequired        bool                             `json:"confirmation_still_required"`
	MutationPermitted                bool                             `json:"mutation_permitted"`
	ExecutionSupported               bool                             `json:"execution_supported"`
	Operations                       []OrderedFullFlashWriteOperation `json:"operations"`
	PlanSHA256                       string                           `json:"plan_sha256"`
	Warnings                         []string                         `json:"warnings"`
	Limitations                      []string                         `json:"limitations"`
}

type fullFlashWriteExtentKey struct {
	descriptor uint32
	location   uint32
}

// PlanSinglePhaseFullFlashWriteOrder correlates an authenticated descriptor
// plan, exact target plan, and full-flash validation plan. It accepts only a
// single-phase desktop-style payload profile whose final table range covers all
// sequential payload blocks. Staged-GPT profiles remain refused until their
// ordering semantics are independently specified and qualified.
func PlanSinglePhaseFullFlashWriteOrder(
	descriptor DescriptorPlan,
	target RestoreTargetPlan,
	full FullFlashValidationPlan,
) (FullFlashWriteOrderPlan, error) {
	if err := validateRestoreTargetPlan(target); err != nil {
		return FullFlashWriteOrderPlan{}, fmt.Errorf("validate prerequisite FFU target plan: %w", err)
	}
	if err := validateFullFlashValidationPlan(full); err != nil {
		return FullFlashWriteOrderPlan{}, fmt.Errorf("validate prerequisite FFU full-flash plan: %w", err)
	}
	if descriptor.Schema != 1 || descriptor.StoreMajorVersion != 1 || descriptor.StoreMinorVersion != 0 || descriptor.SourceFileSize == 0 || descriptor.BlockSizeBytes == 0 || descriptor.ExecutionSupported || descriptor.IntegrityAuthenticated || descriptor.HasDestinationOverlap {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order planning requires the unchanged non-executable single-store-v1 descriptor plan")
	}
	if descriptor.PlanSHA256 != descriptorPlanDigest(descriptor) {
		return FullFlashWriteOrderPlan{}, errors.New("FFU descriptor-plan evidence was altered")
	}
	if descriptor.PlanSHA256 != target.DescriptorPlanSHA256 || descriptor.PlanSHA256 != full.DescriptorPlanSHA256 || target.PlanSHA256 != full.RestoreTargetPlanSHA256 {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order prerequisites disagree on descriptor or target-plan identity")
	}
	if target.AuthenticatedIntegrityPlanSHA256 != full.AuthenticatedIntegrityPlanSHA256 || target.CatalogSHA256 != full.CatalogSHA256 || target.HashTableSHA256 != full.HashTableSHA256 {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order prerequisites disagree on authenticated source evidence")
	}
	if descriptor.SourceFileSize != target.SourceFileSize || descriptor.SourceFileSize != full.SourceFileSize || descriptor.BlockSizeBytes != target.StoreBlockSizeBytes || descriptor.BlockSizeBytes != full.StoreBlockSizeBytes {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order prerequisites disagree on source or block geometry")
	}
	if target.DevicePath != full.DevicePath || target.ExpectedTargetIdentity != full.ExpectedTargetIdentity || target.TargetSizeBytes != full.TargetSizeBytes || target.TargetBlockCount != full.TargetBlockCount || target.MutationBytes != full.MutationBytes {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order prerequisites disagree on exact target facts")
	}
	if len(descriptor.ValidationDescriptors) != 0 || target.ValidationDescriptorCount != 0 || full.ValidationDescriptorCount != 0 || target.ValidationChecksRequired || !full.ValidationChecksResolved {
		return FullFlashWriteOrderPlan{}, errors.New("FFU write-order planning requires the resolved full-flash profile with no validation descriptors")
	}
	if !emptyCanonicalPayloadTableRange(descriptor.InitialTable) || !emptyCanonicalPayloadTableRange(descriptor.FlashOnlyTable) {
		return FullFlashWriteOrderPlan{}, errors.New("FFU staged GPT payload ranges are unsupported: initial and flash-only ranges must both be absent")
	}
	if descriptor.TotalPayloadBlocks == 0 || descriptor.FinalTable.BlockIndex != 0 || descriptor.FinalTable.BlockEnd != descriptor.TotalPayloadBlocks || uint64(descriptor.FinalTable.BlockCount) != descriptor.TotalPayloadBlocks {
		return FullFlashWriteOrderPlan{}, errors.New("FFU single-phase profile requires the final table range to cover the complete sequential payload")
	}
	payloadLength, err := checkedMul(descriptor.TotalPayloadBlocks, descriptor.BlockSizeBytes)
	if err != nil || payloadLength == 0 || payloadLength != descriptor.PayloadLength {
		return FullFlashWriteOrderPlan{}, errors.New("FFU descriptor payload block accounting is inconsistent")
	}
	payloadEnd, err := checkedAdd(descriptor.PayloadOffset, descriptor.PayloadLength)
	if err != nil || payloadEnd != descriptor.PayloadEnd || payloadEnd > descriptor.SourceFileSize || descriptor.PayloadFileBytes != descriptor.SourceFileSize-descriptor.PayloadOffset || descriptor.TrailingFileBytes != descriptor.SourceFileSize-descriptor.PayloadEnd {
		return FullFlashWriteOrderPlan{}, errors.New("FFU descriptor payload byte geometry is inconsistent")
	}
	if len(descriptor.WriteDescriptors) == 0 {
		return FullFlashWriteOrderPlan{}, errors.New("FFU single-phase profile contains no write descriptors")
	}

	extents := make(map[fullFlashWriteExtentKey]ResolvedWriteExtent, len(target.ResolvedWriteExtents))
	for _, extent := range target.ResolvedWriteExtents {
		key := fullFlashWriteExtentKey{descriptor: extent.DescriptorIndex, location: extent.LocationIndex}
		if _, exists := extents[key]; exists {
			return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU target plan contains duplicate extent identity %d:%d", extent.DescriptorIndex, extent.LocationIndex)
		}
		extents[key] = extent
	}

	operations := make([]OrderedFullFlashWriteOperation, 0, len(target.ResolvedWriteExtents))
	payloadCursor := descriptor.PayloadOffset
	totalBlocks := uint64(0)
	mutationBytes := uint64(0)
	sequence := uint64(0)
	for descriptorIndex, write := range descriptor.WriteDescriptors {
		if write.Index != uint32(descriptorIndex) || write.LocationCount == 0 || write.LocationCount != uint32(len(write.Locations)) || write.BlockCount == 0 {
			return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d declaration order or counts are inconsistent", descriptorIndex)
		}
		expectedPayloadLength, mulErr := checkedMul(uint64(write.BlockCount), descriptor.BlockSizeBytes)
		if mulErr != nil || write.PayloadOffset != payloadCursor || write.PayloadLength != expectedPayloadLength {
			return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d payload order is inconsistent", descriptorIndex)
		}
		payloadCursor, err = checkedAdd(payloadCursor, write.PayloadLength)
		if err != nil || payloadCursor > descriptor.PayloadEnd {
			return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d payload boundary is inconsistent", descriptorIndex)
		}
		totalBlocks, err = checkedAdd(totalBlocks, uint64(write.BlockCount))
		if err != nil {
			return FullFlashWriteOrderPlan{}, errors.New("FFU write descriptor block accounting overflows")
		}
		for locationIndex, location := range write.Locations {
			if location.Index != uint32(locationIndex) || location.BlockEnd != uint64(location.BlockIndex)+uint64(write.BlockCount) {
				return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d location %d declaration is inconsistent", descriptorIndex, locationIndex)
			}
			var targetStart uint64
			switch location.Anchor {
			case "begin":
				if location.AccessMethod != diskAccessBegin {
					return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d location %d begin anchor has the wrong access method", descriptorIndex, locationIndex)
				}
				targetStart = uint64(location.BlockIndex)
			case "end":
				if location.AccessMethod != diskAccessEnd || target.TargetBlockCount < location.BlockEnd {
					return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d location %d end anchor is inconsistent with the target", descriptorIndex, locationIndex)
				}
				targetStart = target.TargetBlockCount - location.BlockEnd
			default:
				return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d location %d has unsupported anchor %q", descriptorIndex, locationIndex, location.Anchor)
			}
			targetEnd, addErr := checkedAdd(targetStart, uint64(write.BlockCount))
			targetOffset, offsetErr := checkedMul(targetStart, descriptor.BlockSizeBytes)
			if addErr != nil || offsetErr != nil || targetEnd > target.TargetBlockCount {
				return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU write descriptor %d location %d exceeds the target", descriptorIndex, locationIndex)
			}
			key := fullFlashWriteExtentKey{descriptor: write.Index, location: location.Index}
			extent, exists := extents[key]
			if !exists {
				return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU target plan is missing declared extent %d:%d", write.Index, location.Index)
			}
			if extent.Anchor != location.Anchor || extent.TargetStartBlock != targetStart || extent.TargetEndBlock != targetEnd || extent.TargetOffset != targetOffset || extent.TargetLength != write.PayloadLength || extent.PayloadOffset != write.PayloadOffset || extent.PayloadLength != write.PayloadLength {
				return FullFlashWriteOrderPlan{}, fmt.Errorf("FFU target extent %d:%d disagrees with the declared descriptor", write.Index, location.Index)
			}
			delete(extents, key)
			operations = append(operations, OrderedFullFlashWriteOperation{
				Sequence:         sequence,
				DescriptorIndex:  write.Index,
				LocationIndex:    location.Index,
				Anchor:           location.Anchor,
				TargetStartBlock: targetStart,
				TargetEndBlock:   targetEnd,
				TargetOffset:     targetOffset,
				TargetLength:     write.PayloadLength,
				PayloadOffset:    write.PayloadOffset,
				PayloadLength:    write.PayloadLength,
			})
			sequence++
			mutationBytes, err = checkedAdd(mutationBytes, write.PayloadLength)
			if err != nil {
				return FullFlashWriteOrderPlan{}, errors.New("FFU ordered mutation accounting overflows")
			}
		}
	}
	if len(extents) != 0 {
		return FullFlashWriteOrderPlan{}, errors.New("FFU target plan contains extents not declared by the descriptor plan")
	}
	if payloadCursor != descriptor.PayloadEnd || totalBlocks != descriptor.TotalPayloadBlocks || mutationBytes != target.MutationBytes || uint64(len(operations)) != target.WriteExtentCount {
		return FullFlashWriteOrderPlan{}, errors.New("FFU ordered descriptor, payload, or mutation accounting is inconsistent")
	}

	plan := FullFlashWriteOrderPlan{
		Schema:                           fullFlashWriteOrderPlanSchema,
		Mode:                             "ffu-single-phase-write-order",
		Destructive:                      true,
		DescriptorPlanSHA256:             descriptor.PlanSHA256,
		RestoreTargetPlanSHA256:          target.PlanSHA256,
		FullFlashValidationPlanSHA256:    full.PlanSHA256,
		AuthenticatedIntegrityPlanSHA256: full.AuthenticatedIntegrityPlanSHA256,
		CatalogSHA256:                    full.CatalogSHA256,
		HashTableSHA256:                  full.HashTableSHA256,
		SourceFileSize:                   descriptor.SourceFileSize,
		DevicePath:                       target.DevicePath,
		ExpectedTargetIdentity:           target.ExpectedTargetIdentity,
		TargetSizeBytes:                  target.TargetSizeBytes,
		StoreBlockSizeBytes:              descriptor.BlockSizeBytes,
		TargetBlockCount:                 target.TargetBlockCount,
		PayloadOffset:                    descriptor.PayloadOffset,
		PayloadLength:                    descriptor.PayloadLength,
		PayloadEnd:                       descriptor.PayloadEnd,
		TotalPayloadBlocks:               descriptor.TotalPayloadBlocks,
		InitialTable:                     descriptor.InitialTable,
		FlashOnlyTable:                   descriptor.FlashOnlyTable,
		FinalTable:                       descriptor.FinalTable,
		WriteDescriptorCount:             uint64(len(descriptor.WriteDescriptors)),
		OperationCount:                   uint64(len(operations)),
		MutationBytes:                    mutationBytes,
		SinglePhasePayloadProfile:        true,
		SpecialGPTPhasesAbsent:           true,
		FinalTableCoversPayload:          true,
		DeclaredDescriptorOrderPreserved: true,
		ConfirmationPhrase:               full.ConfirmationPhrase,
		ConfirmationStillRequired:        true,
		MutationPermitted:                false,
		ExecutionSupported:               false,
		Operations:                       operations,
		Warnings:                         fullFlashWriteOrderWarnings(),
		Limitations:                      fullFlashWriteOrderLimitations(),
	}
	plan.PlanSHA256 = fullFlashWriteOrderPlanDigest(plan)
	if err := validateFullFlashWriteOrderPlan(plan); err != nil {
		return FullFlashWriteOrderPlan{}, err
	}
	return plan, nil
}

func emptyCanonicalPayloadTableRange(value PayloadTableRange) bool {
	return value.BlockIndex == 0 && value.BlockCount == 0 && value.BlockEnd == 0
}

func validateFullFlashWriteOrderPlan(plan FullFlashWriteOrderPlan) error {
	if plan.Schema != fullFlashWriteOrderPlanSchema || plan.Mode != "ffu-single-phase-write-order" || !plan.Destructive || !plan.SinglePhasePayloadProfile || !plan.SpecialGPTPhasesAbsent || !plan.FinalTableCoversPayload || !plan.DeclaredDescriptorOrderPreserved || !plan.ConfirmationStillRequired || plan.MutationPermitted || plan.ExecutionSupported {
		return errors.New("invalid FFU single-phase write-order envelope")
	}
	for _, value := range []string{
		plan.DescriptorPlanSHA256,
		plan.RestoreTargetPlanSHA256,
		plan.FullFlashValidationPlanSHA256,
		plan.AuthenticatedIntegrityPlanSHA256,
		plan.CatalogSHA256,
		plan.HashTableSHA256,
	} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU single-phase write-order plan contains an invalid SHA-256 evidence identifier")
		}
	}
	if plan.SourceFileSize == 0 || plan.TargetSizeBytes == 0 || plan.StoreBlockSizeBytes == 0 || plan.TargetBlockCount != plan.TargetSizeBytes/plan.StoreBlockSizeBytes || plan.TargetSizeBytes%plan.StoreBlockSizeBytes != 0 {
		return errors.New("FFU single-phase write-order target geometry is inconsistent")
	}
	if !emptyCanonicalPayloadTableRange(plan.InitialTable) || !emptyCanonicalPayloadTableRange(plan.FlashOnlyTable) || plan.TotalPayloadBlocks == 0 || plan.FinalTable.BlockIndex != 0 || plan.FinalTable.BlockEnd != plan.TotalPayloadBlocks || uint64(plan.FinalTable.BlockCount) != plan.TotalPayloadBlocks {
		return errors.New("FFU single-phase write-order table profile is inconsistent")
	}
	expectedPayloadLength, mulErr := checkedMul(plan.TotalPayloadBlocks, plan.StoreBlockSizeBytes)
	expectedPayloadEnd, addErr := checkedAdd(plan.PayloadOffset, plan.PayloadLength)
	if mulErr != nil || addErr != nil || plan.PayloadLength != expectedPayloadLength || plan.PayloadEnd != expectedPayloadEnd || plan.PayloadEnd > plan.SourceFileSize || plan.WriteDescriptorCount == 0 || plan.OperationCount != uint64(len(plan.Operations)) || plan.MutationBytes == 0 || plan.MutationBytes > plan.TargetSizeBytes {
		return errors.New("FFU single-phase write-order payload or operation accounting is inconsistent")
	}
	mutationBytes := uint64(0)
	for index, operation := range plan.Operations {
		expectedOffset, offsetErr := checkedMul(operation.TargetStartBlock, plan.StoreBlockSizeBytes)
		expectedLength, lengthErr := checkedMul(operation.TargetEndBlock-operation.TargetStartBlock, plan.StoreBlockSizeBytes)
		payloadEnd, payloadErr := checkedAdd(operation.PayloadOffset, operation.PayloadLength)
		if operation.Sequence != uint64(index) || operation.DescriptorIndex >= uint32(plan.WriteDescriptorCount) || (operation.Anchor != "begin" && operation.Anchor != "end") || operation.TargetStartBlock >= operation.TargetEndBlock || operation.TargetEndBlock > plan.TargetBlockCount || offsetErr != nil || lengthErr != nil || payloadErr != nil || operation.TargetOffset != expectedOffset || operation.TargetLength != expectedLength || operation.PayloadLength != operation.TargetLength || operation.PayloadOffset < plan.PayloadOffset || payloadEnd > plan.PayloadEnd {
			return fmt.Errorf("FFU single-phase write-order operation %d is inconsistent", index)
		}
		var err error
		mutationBytes, err = checkedAdd(mutationBytes, operation.TargetLength)
		if err != nil {
			return errors.New("FFU single-phase write-order mutation accounting overflows")
		}
	}
	expectedPhrase := fmt.Sprintf("RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES", plan.DevicePath, plan.TargetSizeBytes)
	if plan.DevicePath == "" || plan.ExpectedTargetIdentity == "" || plan.ConfirmationPhrase != expectedPhrase || mutationBytes != plan.MutationBytes || !equalRestoreStrings(plan.Warnings, fullFlashWriteOrderWarnings()) || !equalRestoreStrings(plan.Limitations, fullFlashWriteOrderLimitations()) || plan.PlanSHA256 != fullFlashWriteOrderPlanDigest(plan) {
		return errors.New("FFU single-phase write-order evidence, confirmation, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashWriteOrderWarnings() []string {
	return []string{
		"This plan describes destructive writes but deliberately grants no permission to perform them.",
		"Only the unambiguous single-phase profile with no initial or flash-only GPT payload range is accepted.",
		"The authenticated source lease, exclusive target session, and exact destructive confirmation must remain healthy through any future authorization and execution.",
		"Software restoration cannot prove physical bootability or complete device health.",
	}
}

func fullFlashWriteOrderLimitations() []string {
	return []string{
		"staged-GPT and mobile-style FFU profiles remain refused rather than assigned inferred ordering semantics",
		"the plan exposes no source or target descriptor and performs no read, write, seek, sync, ioctl, unmount, or privilege operation",
		"cancellation result states, first-mutation authorization, flush, readback, changed-media handling, and provider qualification remain separate gates",
		"mutation_permitted and execution_supported remain false",
	}
}

func fullFlashWriteOrderPlanDigest(plan FullFlashWriteOrderPlan) string {
	digest := sha256.New()
	writeFullFlashWriteOrderUint64(digest, uint64(plan.Schema))
	writeFullFlashWriteOrderString(digest, plan.Mode)
	writeFullFlashWriteOrderBool(digest, plan.Destructive)
	writeFullFlashWriteOrderString(digest, plan.DescriptorPlanSHA256)
	writeFullFlashWriteOrderString(digest, plan.RestoreTargetPlanSHA256)
	writeFullFlashWriteOrderString(digest, plan.FullFlashValidationPlanSHA256)
	writeFullFlashWriteOrderString(digest, plan.AuthenticatedIntegrityPlanSHA256)
	writeFullFlashWriteOrderString(digest, plan.CatalogSHA256)
	writeFullFlashWriteOrderString(digest, plan.HashTableSHA256)
	writeFullFlashWriteOrderUint64(digest, plan.SourceFileSize)
	writeFullFlashWriteOrderString(digest, plan.DevicePath)
	writeFullFlashWriteOrderString(digest, plan.ExpectedTargetIdentity)
	writeFullFlashWriteOrderUint64(digest, plan.TargetSizeBytes)
	writeFullFlashWriteOrderUint64(digest, plan.StoreBlockSizeBytes)
	writeFullFlashWriteOrderUint64(digest, plan.TargetBlockCount)
	writeFullFlashWriteOrderUint64(digest, plan.PayloadOffset)
	writeFullFlashWriteOrderUint64(digest, plan.PayloadLength)
	writeFullFlashWriteOrderUint64(digest, plan.PayloadEnd)
	writeFullFlashWriteOrderUint64(digest, plan.TotalPayloadBlocks)
	writeFullFlashWriteOrderPayloadRange(digest, plan.InitialTable)
	writeFullFlashWriteOrderPayloadRange(digest, plan.FlashOnlyTable)
	writeFullFlashWriteOrderPayloadRange(digest, plan.FinalTable)
	writeFullFlashWriteOrderUint64(digest, plan.WriteDescriptorCount)
	writeFullFlashWriteOrderUint64(digest, plan.OperationCount)
	writeFullFlashWriteOrderUint64(digest, plan.MutationBytes)
	writeFullFlashWriteOrderBool(digest, plan.SinglePhasePayloadProfile)
	writeFullFlashWriteOrderBool(digest, plan.SpecialGPTPhasesAbsent)
	writeFullFlashWriteOrderBool(digest, plan.FinalTableCoversPayload)
	writeFullFlashWriteOrderBool(digest, plan.DeclaredDescriptorOrderPreserved)
	writeFullFlashWriteOrderString(digest, plan.ConfirmationPhrase)
	writeFullFlashWriteOrderBool(digest, plan.ConfirmationStillRequired)
	writeFullFlashWriteOrderBool(digest, plan.MutationPermitted)
	writeFullFlashWriteOrderBool(digest, plan.ExecutionSupported)
	for _, operation := range plan.Operations {
		writeFullFlashWriteOrderUint64(digest, operation.Sequence)
		writeFullFlashWriteOrderUint64(digest, uint64(operation.DescriptorIndex))
		writeFullFlashWriteOrderUint64(digest, uint64(operation.LocationIndex))
		writeFullFlashWriteOrderString(digest, operation.Anchor)
		writeFullFlashWriteOrderUint64(digest, operation.TargetStartBlock)
		writeFullFlashWriteOrderUint64(digest, operation.TargetEndBlock)
		writeFullFlashWriteOrderUint64(digest, operation.TargetOffset)
		writeFullFlashWriteOrderUint64(digest, operation.TargetLength)
		writeFullFlashWriteOrderUint64(digest, operation.PayloadOffset)
		writeFullFlashWriteOrderUint64(digest, operation.PayloadLength)
	}
	for _, warning := range plan.Warnings {
		writeFullFlashWriteOrderString(digest, warning)
	}
	for _, limitation := range plan.Limitations {
		writeFullFlashWriteOrderString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeFullFlashWriteOrderPayloadRange(digest hash.Hash, value PayloadTableRange) {
	writeFullFlashWriteOrderUint64(digest, uint64(value.BlockIndex))
	writeFullFlashWriteOrderUint64(digest, uint64(value.BlockCount))
	writeFullFlashWriteOrderUint64(digest, value.BlockEnd)
}

func writeFullFlashWriteOrderUint64(digest hash.Hash, value uint64) {
	writeRestoreUint64(digest, value)
}

func writeFullFlashWriteOrderString(digest hash.Hash, value string) {
	writeRestoreString(digest, value)
}

func writeFullFlashWriteOrderBool(digest hash.Hash, value bool) {
	writeRestoreBool(digest, value)
}
