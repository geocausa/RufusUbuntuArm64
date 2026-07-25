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
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const restoreTargetPlanSchema = 1

// RestoreTargetRequest contains immutable target facts discovered without
// privileges. A future privileged provider must rediscover and revalidate every
// field before any mutation.
type RestoreTargetRequest struct {
	DevicePath             string `json:"device_path"`
	ExpectedTargetIdentity string `json:"expected_target_identity"`
	TargetSizeBytes        uint64 `json:"target_size_bytes"`
	LogicalSectorSizeBytes uint64 `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes uint64 `json:"physical_sector_size_bytes"`
}

// ResolvedWriteExtent binds one FFU destination expression to exact target and
// source-payload byte ranges. It grants no authority to open either path.
type ResolvedWriteExtent struct {
	DescriptorIndex uint32 `json:"descriptor_index"`
	LocationIndex   uint32 `json:"location_index"`
	Anchor          string `json:"anchor"`
	TargetStartBlock uint64 `json:"target_start_block"`
	TargetEndBlock   uint64 `json:"target_end_block"`
	TargetOffset     uint64 `json:"target_offset"`
	TargetLength     uint64 `json:"target_length"`
	PayloadOffset    uint64 `json:"payload_offset"`
	PayloadLength    uint64 `json:"payload_length"`
}

// RestoreTargetPlan is a deterministic, non-privileged review plan for one
// authenticated single-store-v1 FFU and one exact target. Validation reads and
// all writes remain disabled.
type RestoreTargetPlan struct {
	Schema                          int                   `json:"schema"`
	Mode                            string                `json:"mode"`
	Destructive                     bool                  `json:"destructive"`
	SourceFileSize                  uint64                `json:"source_file_size"`
	AuthenticatedIntegrityPlanSHA256 string               `json:"authenticated_integrity_plan_sha256"`
	DescriptorPlanSHA256            string                `json:"descriptor_plan_sha256"`
	CatalogSHA256                   string                `json:"catalog_sha256"`
	HashTableSHA256                 string                `json:"hash_table_sha256"`
	DevicePath                      string                `json:"device_path"`
	ExpectedTargetIdentity          string                `json:"expected_target_identity"`
	TargetSizeBytes                 uint64                `json:"target_size_bytes"`
	LogicalSectorSizeBytes          uint64                `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes         uint64                `json:"physical_sector_size_bytes"`
	StoreBlockSizeBytes             uint64                `json:"store_block_size_bytes"`
	TargetBlockCount                uint64                `json:"target_block_count"`
	MinimumTargetBytes              uint64                `json:"minimum_target_bytes"`
	WriteExtentCount                uint64                `json:"write_extent_count"`
	MutationBytes                   uint64                `json:"mutation_bytes"`
	ResolvedWriteExtents            []ResolvedWriteExtent `json:"resolved_write_extents"`
	ValidationDescriptorCount       uint64                `json:"validation_descriptor_count"`
	SourceIntegrityAuthenticated    bool                  `json:"source_integrity_authenticated"`
	TargetIdentityBound             bool                  `json:"target_identity_bound"`
	TargetGeometryBound             bool                  `json:"target_geometry_bound"`
	DestinationMapResolved          bool                  `json:"destination_map_resolved"`
	DestinationOverlap              bool                  `json:"destination_overlap"`
	ValidationChecksRequired        bool                  `json:"validation_checks_required"`
	ValidationChecksResolved        bool                  `json:"validation_checks_resolved"`
	ConfirmationRequired            bool                  `json:"confirmation_required"`
	ExecutionSupported              bool                  `json:"execution_supported"`
	PlanSHA256                      string                `json:"plan_sha256"`
	Warnings                        []string              `json:"warnings"`
	Limitations                     []string              `json:"limitations"`
}

// BindAuthenticatedSingleStoreV1Target re-runs complete read-only source
// authentication, canonicalizes one target identity and geometry, resolves all
// beginning/end-relative write expressions, and rejects every overlap. It does
// not open the target or execute validation descriptors.
func BindAuthenticatedSingleStoreV1Target(ctx context.Context, reader io.ReaderAt, sourceSize uint64, activation TrustBundleActivation, evaluationTime time.Time, sourcePolicy CatalogPublisherPolicy, request RestoreTargetRequest) (Inspection, DescriptorPlan, HashTablePlan, ContentVerification, CatalogHashAuthenticationPlan, AuthenticatedIntegrityPlan, RestoreTargetPlan, error) {
	if ctx == nil {
		return Inspection{}, DescriptorPlan{}, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, RestoreTargetPlan{}, errors.New("FFU target-plan context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, DescriptorPlan{}, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, RestoreTargetPlan{}, err
	}

	canonicalRequest, err := validateRestoreTargetRequest(request)
	if err != nil {
		return Inspection{}, DescriptorPlan{}, HashTablePlan{}, ContentVerification{}, CatalogHashAuthenticationPlan{}, AuthenticatedIntegrityPlan{}, RestoreTargetPlan{}, err
	}
	inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, err := AuthenticateSingleStoreV1Integrity(ctx, reader, sourceSize, activation, evaluationTime, sourcePolicy)
	if err != nil {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, err
	}
	if !integrityPlan.IntegrityAuthenticated || !integrityPlan.HashTableCatalogAuthenticated || !integrityPlan.ContentMatchesHashTable {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, errors.New("FFU target planning requires complete authenticated source integrity")
	}
	if descriptor.HasDestinationOverlap {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, errors.New("FFU target planning refuses same-anchor destination overlap")
	}
	if descriptor.BlockSizeBytes == 0 || canonicalRequest.TargetSizeBytes < descriptor.MinimumTargetBytes {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, fmt.Errorf("FFU target size %d is smaller than required minimum %d", canonicalRequest.TargetSizeBytes, descriptor.MinimumTargetBytes)
	}
	if canonicalRequest.TargetSizeBytes%descriptor.BlockSizeBytes != 0 {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, fmt.Errorf("FFU target size %d is not aligned to store block size %d", canonicalRequest.TargetSizeBytes, descriptor.BlockSizeBytes)
	}
	if descriptor.BlockSizeBytes%canonicalRequest.LogicalSectorSizeBytes != 0 || descriptor.BlockSizeBytes%canonicalRequest.PhysicalSectorSizeBytes != 0 {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, errors.New("FFU store block size is incompatible with target sector geometry")
	}
	targetBlocks := canonicalRequest.TargetSizeBytes / descriptor.BlockSizeBytes
	extents, mutationBytes, err := resolveRestoreWriteExtents(descriptor, targetBlocks)
	if err != nil {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, err
	}

	plan := RestoreTargetPlan{
		Schema:                           restoreTargetPlanSchema,
		Mode:                             "ffu-restore",
		Destructive:                      true,
		SourceFileSize:                   sourceSize,
		AuthenticatedIntegrityPlanSHA256: integrityPlan.PlanSHA256,
		DescriptorPlanSHA256:             descriptor.PlanSHA256,
		CatalogSHA256:                    integrityPlan.CatalogSHA256,
		HashTableSHA256:                  integrityPlan.HashTableSHA256,
		DevicePath:                       canonicalRequest.DevicePath,
		ExpectedTargetIdentity:           canonicalRequest.ExpectedTargetIdentity,
		TargetSizeBytes:                  canonicalRequest.TargetSizeBytes,
		LogicalSectorSizeBytes:           canonicalRequest.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes:          canonicalRequest.PhysicalSectorSizeBytes,
		StoreBlockSizeBytes:              descriptor.BlockSizeBytes,
		TargetBlockCount:                 targetBlocks,
		MinimumTargetBytes:               descriptor.MinimumTargetBytes,
		WriteExtentCount:                 uint64(len(extents)),
		MutationBytes:                    mutationBytes,
		ResolvedWriteExtents:             extents,
		ValidationDescriptorCount:        uint64(len(descriptor.ValidationDescriptors)),
		SourceIntegrityAuthenticated:     true,
		TargetIdentityBound:              true,
		TargetGeometryBound:              true,
		DestinationMapResolved:           true,
		DestinationOverlap:               false,
		ValidationChecksRequired:         len(descriptor.ValidationDescriptors) != 0,
		ValidationChecksResolved:         false,
		ConfirmationRequired:             true,
		ExecutionSupported:               false,
		Warnings:                         restoreTargetWarnings(),
		Limitations: []string{
			"the plan is bound to caller-discovered target facts but opens no device",
			"a privileged provider must independently rediscover and revalidate identity, size, sector geometry, source evidence, and the complete plan",
			"target-side validation descriptor semantics, cancellation, write ordering, flush, readback, and changed-media reporting remain unresolved",
			"software planning and verification cannot prove physical bootability or whole-device health",
		},
	}
	plan.PlanSHA256 = restoreTargetPlanDigest(plan)
	if err := validateRestoreTargetPlan(plan); err != nil {
		return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, RestoreTargetPlan{}, err
	}
	return inspection, descriptor, hashPlan, verification, catalogPlan, integrityPlan, plan, nil
}

// RestoreTargetConfirmationPhrase returns the exact destructive phrase for the
// already validated target plan. It does not authorize or perform execution.
func RestoreTargetConfirmationPhrase(plan RestoreTargetPlan) (string, error) {
	if err := validateRestoreTargetPlan(plan); err != nil {
		return "", err
	}
	return fmt.Sprintf("RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES", plan.DevicePath, plan.TargetSizeBytes), nil
}

func validateRestoreTargetRequest(request RestoreTargetRequest) (RestoreTargetRequest, error) {
	path := strings.TrimSpace(request.DevicePath)
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path || path != request.DevicePath {
		return RestoreTargetRequest{}, fmt.Errorf("FFU target path must be a canonical absolute path beneath /dev, not %q", request.DevicePath)
	}
	identity := strings.TrimSpace(request.ExpectedTargetIdentity)
	if identity == "" || identity != request.ExpectedTargetIdentity || len(identity) > 4096 {
		return RestoreTargetRequest{}, errors.New("FFU expected target identity must be non-empty, canonical, and bounded")
	}
	if request.TargetSizeBytes == 0 {
		return RestoreTargetRequest{}, errors.New("FFU target size is zero")
	}
	if !validFFUTargetSectorSize(request.LogicalSectorSizeBytes) || !validFFUTargetSectorSize(request.PhysicalSectorSizeBytes) || request.PhysicalSectorSizeBytes < request.LogicalSectorSizeBytes || request.PhysicalSectorSizeBytes%request.LogicalSectorSizeBytes != 0 {
		return RestoreTargetRequest{}, errors.New("FFU target sector geometry is invalid")
	}
	if request.TargetSizeBytes%request.LogicalSectorSizeBytes != 0 || request.TargetSizeBytes%request.PhysicalSectorSizeBytes != 0 {
		return RestoreTargetRequest{}, errors.New("FFU target size is not aligned to target sector geometry")
	}
	return request, nil
}

func validFFUTargetSectorSize(value uint64) bool {
	return value >= 512 && value <= 65536 && value&(value-1) == 0
}

func resolveRestoreWriteExtents(descriptor DescriptorPlan, targetBlocks uint64) ([]ResolvedWriteExtent, uint64, error) {
	extents := make([]ResolvedWriteExtent, 0)
	for _, write := range descriptor.WriteDescriptors {
		if write.BlockCount == 0 || write.PayloadLength == 0 || write.PayloadLength != uint64(write.BlockCount)*descriptor.BlockSizeBytes {
			return nil, 0, fmt.Errorf("FFU write descriptor %d has inconsistent payload geometry", write.Index)
		}
		for _, location := range write.Locations {
			var start uint64
			switch location.Anchor {
			case "begin":
				start = uint64(location.BlockIndex)
			case "end":
				if targetBlocks < location.BlockEnd {
					return nil, 0, fmt.Errorf("FFU end-relative destination %d:%d exceeds target block count %d", write.Index, location.Index, targetBlocks)
				}
				start = targetBlocks - location.BlockEnd
			default:
				return nil, 0, fmt.Errorf("FFU write descriptor %d location %d has unsupported anchor %q", write.Index, location.Index, location.Anchor)
			}
			end, err := checkedAdd(start, uint64(write.BlockCount))
			if err != nil || end > targetBlocks {
				return nil, 0, fmt.Errorf("FFU destination %d:%d exceeds target block count %d", write.Index, location.Index, targetBlocks)
			}
			offset, err := checkedMul(start, descriptor.BlockSizeBytes)
			if err != nil {
				return nil, 0, fmt.Errorf("FFU destination %d:%d byte offset overflows", write.Index, location.Index)
			}
			length, err := checkedMul(uint64(write.BlockCount), descriptor.BlockSizeBytes)
			if err != nil || length != write.PayloadLength {
				return nil, 0, fmt.Errorf("FFU destination %d:%d byte length is inconsistent", write.Index, location.Index)
			}
			extents = append(extents, ResolvedWriteExtent{
				DescriptorIndex:  write.Index,
				LocationIndex:    location.Index,
				Anchor:           location.Anchor,
				TargetStartBlock: start,
				TargetEndBlock:   end,
				TargetOffset:     offset,
				TargetLength:     length,
				PayloadOffset:    write.PayloadOffset,
				PayloadLength:    write.PayloadLength,
			})
		}
	}
	sort.Slice(extents, func(left, right int) bool {
		if extents[left].TargetStartBlock != extents[right].TargetStartBlock {
			return extents[left].TargetStartBlock < extents[right].TargetStartBlock
		}
		if extents[left].TargetEndBlock != extents[right].TargetEndBlock {
			return extents[left].TargetEndBlock < extents[right].TargetEndBlock
		}
		if extents[left].DescriptorIndex != extents[right].DescriptorIndex {
			return extents[left].DescriptorIndex < extents[right].DescriptorIndex
		}
		return extents[left].LocationIndex < extents[right].LocationIndex
	})
	mutationBytes := uint64(0)
	for index, extent := range extents {
		if index != 0 && extent.TargetStartBlock < extents[index-1].TargetEndBlock {
			return nil, 0, fmt.Errorf("FFU target-specific destination overlap between %d:%d and %d:%d", extents[index-1].DescriptorIndex, extents[index-1].LocationIndex, extent.DescriptorIndex, extent.LocationIndex)
		}
		var err error
		mutationBytes, err = checkedAdd(mutationBytes, extent.TargetLength)
		if err != nil {
			return nil, 0, errors.New("FFU target mutation byte count overflows")
		}
	}
	return extents, mutationBytes, nil
}

func validateRestoreTargetPlan(plan RestoreTargetPlan) error {
	if plan.Schema != restoreTargetPlanSchema || plan.Mode != "ffu-restore" || !plan.Destructive || !plan.SourceIntegrityAuthenticated || !plan.TargetIdentityBound || !plan.TargetGeometryBound || !plan.DestinationMapResolved || plan.DestinationOverlap || !plan.ConfirmationRequired || plan.ExecutionSupported || plan.ValidationChecksResolved {
		return errors.New("invalid FFU restore target-plan envelope")
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
	if plan.StoreBlockSizeBytes == 0 || plan.TargetSizeBytes%plan.StoreBlockSizeBytes != 0 || plan.TargetBlockCount != plan.TargetSizeBytes/plan.StoreBlockSizeBytes || plan.TargetSizeBytes < plan.MinimumTargetBytes || plan.WriteExtentCount != uint64(len(plan.ResolvedWriteExtents)) || plan.ValidationChecksRequired != (plan.ValidationDescriptorCount != 0) {
		return errors.New("FFU restore target-plan geometry or accounting is inconsistent")
	}
	if plan.StoreBlockSizeBytes%plan.LogicalSectorSizeBytes != 0 || plan.StoreBlockSizeBytes%plan.PhysicalSectorSizeBytes != 0 {
		return errors.New("FFU restore target-plan sector binding is inconsistent")
	}
	mutationBytes := uint64(0)
	for index, extent := range plan.ResolvedWriteExtents {
		if extent.Anchor != "begin" && extent.Anchor != "end" || extent.TargetStartBlock >= extent.TargetEndBlock || extent.TargetEndBlock > plan.TargetBlockCount || extent.TargetOffset != extent.TargetStartBlock*plan.StoreBlockSizeBytes || extent.TargetLength != (extent.TargetEndBlock-extent.TargetStartBlock)*plan.StoreBlockSizeBytes || extent.PayloadLength != extent.TargetLength {
			return fmt.Errorf("FFU restore target-plan extent %d is inconsistent", index)
		}
		if index != 0 && extent.TargetStartBlock < plan.ResolvedWriteExtents[index-1].TargetEndBlock {
			return errors.New("FFU restore target-plan contains overlapping extents")
		}
		var err error
		mutationBytes, err = checkedAdd(mutationBytes, extent.TargetLength)
		if err != nil {
			return errors.New("FFU restore target-plan mutation accounting overflows")
		}
	}
	if mutationBytes != plan.MutationBytes || plan.PlanSHA256 != restoreTargetPlanDigest(plan) || !equalRestoreStrings(plan.Warnings, restoreTargetWarnings()) {
		return errors.New("FFU restore target-plan evidence or warnings were altered")
	}
	return nil
}

func equalRestoreStrings(left, right []string) bool {
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

func restoreTargetWarnings() []string {
	return []string{
		"Restoring an FFU is destructive and can overwrite partition tables and data on the complete selected target.",
		"The exact target identity, capacity, and sector geometry must be rediscovered and match immediately before any future write.",
		"FFU validation descriptors are not yet resolved or executed, so this plan cannot authorize restoration.",
		"Software authentication and restoration cannot prove that the resulting device will boot or that the complete device is healthy.",
	}
}

func restoreTargetPlanDigest(plan RestoreTargetPlan) string {
	digest := sha256.New()
	writeRestoreUint64(digest, uint64(plan.Schema))
	writeRestoreString(digest, plan.Mode)
	writeRestoreBool(digest, plan.Destructive)
	writeRestoreUint64(digest, plan.SourceFileSize)
	writeRestoreString(digest, plan.AuthenticatedIntegrityPlanSHA256)
	writeRestoreString(digest, plan.DescriptorPlanSHA256)
	writeRestoreString(digest, plan.CatalogSHA256)
	writeRestoreString(digest, plan.HashTableSHA256)
	writeRestoreString(digest, plan.DevicePath)
	writeRestoreString(digest, plan.ExpectedTargetIdentity)
	writeRestoreUint64(digest, plan.TargetSizeBytes)
	writeRestoreUint64(digest, plan.LogicalSectorSizeBytes)
	writeRestoreUint64(digest, plan.PhysicalSectorSizeBytes)
	writeRestoreUint64(digest, plan.StoreBlockSizeBytes)
	writeRestoreUint64(digest, plan.TargetBlockCount)
	writeRestoreUint64(digest, plan.MinimumTargetBytes)
	writeRestoreUint64(digest, plan.WriteExtentCount)
	writeRestoreUint64(digest, plan.MutationBytes)
	for _, extent := range plan.ResolvedWriteExtents {
		writeRestoreUint64(digest, uint64(extent.DescriptorIndex))
		writeRestoreUint64(digest, uint64(extent.LocationIndex))
		writeRestoreString(digest, extent.Anchor)
		writeRestoreUint64(digest, extent.TargetStartBlock)
		writeRestoreUint64(digest, extent.TargetEndBlock)
		writeRestoreUint64(digest, extent.TargetOffset)
		writeRestoreUint64(digest, extent.TargetLength)
		writeRestoreUint64(digest, extent.PayloadOffset)
		writeRestoreUint64(digest, extent.PayloadLength)
	}
	writeRestoreUint64(digest, plan.ValidationDescriptorCount)
	writeRestoreBool(digest, plan.SourceIntegrityAuthenticated)
	writeRestoreBool(digest, plan.TargetIdentityBound)
	writeRestoreBool(digest, plan.TargetGeometryBound)
	writeRestoreBool(digest, plan.DestinationMapResolved)
	writeRestoreBool(digest, plan.DestinationOverlap)
	writeRestoreBool(digest, plan.ValidationChecksRequired)
	writeRestoreBool(digest, plan.ValidationChecksResolved)
	writeRestoreBool(digest, plan.ConfirmationRequired)
	writeRestoreBool(digest, plan.ExecutionSupported)
	for _, warning := range plan.Warnings {
		writeRestoreString(digest, warning)
	}
	for _, limitation := range plan.Limitations {
		writeRestoreString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeRestoreUint64(digest hash.Hash, value uint64) { writeSignatureUint64(digest, value) }
func writeRestoreString(digest hash.Hash, value string) { writeSignatureString(digest, value) }
func writeRestoreBool(digest hash.Hash, value bool) { writeSignatureBool(digest, value) }
