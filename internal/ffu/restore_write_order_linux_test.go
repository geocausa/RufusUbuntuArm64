//go:build linux

package ffu

import (
	"strings"
	"testing"
)

func TestPlanSinglePhaseFullFlashWriteOrder(t *testing.T) {
	descriptor, target, full := validSinglePhaseWriteOrderFixture()
	plan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.SinglePhasePayloadProfile || !plan.SpecialGPTPhasesAbsent || !plan.FinalTableCoversPayload || !plan.DeclaredDescriptorOrderPreserved || !plan.ConfirmationStillRequired || plan.MutationPermitted || plan.ExecutionSupported {
		t.Fatalf("write-order plan crossed or missed a boundary: %#v", plan)
	}
	if plan.DescriptorPlanSHA256 != descriptor.PlanSHA256 || plan.RestoreTargetPlanSHA256 != target.PlanSHA256 || plan.FullFlashValidationPlanSHA256 != full.PlanSHA256 {
		t.Fatalf("write-order plan lost prerequisite binding: %#v", plan)
	}
	if plan.OperationCount != 3 || len(plan.Operations) != 3 || plan.MutationBytes != target.MutationBytes {
		t.Fatalf("unexpected write-order accounting: %#v", plan)
	}
	// Target-sorted order would start with descriptor 1 at block 0. The plan must
	// preserve declaration order, so descriptor 0 at block 4 remains first.
	first, second, third := plan.Operations[0], plan.Operations[1], plan.Operations[2]
	if first.Sequence != 0 || first.DescriptorIndex != 0 || first.LocationIndex != 0 || first.TargetStartBlock != 4 || first.PayloadOffset != descriptor.WriteDescriptors[0].PayloadOffset {
		t.Fatalf("first declared operation was reordered: %#v", first)
	}
	if second.Sequence != 1 || second.DescriptorIndex != 1 || second.LocationIndex != 0 || second.TargetStartBlock != 0 {
		t.Fatalf("second declared operation is wrong: %#v", second)
	}
	if third.Sequence != 2 || third.DescriptorIndex != 1 || third.LocationIndex != 1 || third.TargetStartBlock != 7 || third.Anchor != "end" {
		t.Fatalf("third declared operation is wrong: %#v", third)
	}
	if plan.PlanSHA256 != fullFlashWriteOrderPlanDigest(plan) {
		t.Fatal("single-phase write-order digest mismatch")
	}

	secondPlan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
	if err != nil {
		t.Fatal(err)
	}
	if secondPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatal("identical prerequisites produced different write-order evidence")
	}
}

func TestPlanSinglePhaseFullFlashWriteOrderRejectsStagedGPTProfiles(t *testing.T) {
	tests := []struct {
		name string
		edit func(*DescriptorPlan)
		want string
	}{
		{
			name: "initial table",
			edit: func(descriptor *DescriptorPlan) {
				descriptor.InitialTable = PayloadTableRange{BlockIndex: 0, BlockCount: 1, BlockEnd: 1}
			},
			want: "staged GPT",
		},
		{
			name: "flash-only table",
			edit: func(descriptor *DescriptorPlan) {
				descriptor.FlashOnlyTable = PayloadTableRange{BlockIndex: 1, BlockCount: 1, BlockEnd: 2}
			},
			want: "staged GPT",
		},
		{
			name: "partial final table",
			edit: func(descriptor *DescriptorPlan) {
				descriptor.FinalTable = PayloadTableRange{BlockIndex: 1, BlockCount: 2, BlockEnd: 3}
			},
			want: "complete sequential payload",
		},
		{
			name: "short final count",
			edit: func(descriptor *DescriptorPlan) {
				descriptor.FinalTable.BlockCount--
			},
			want: "complete sequential payload",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, target, full := validSinglePhaseWriteOrderFixture()
			test.edit(&descriptor)
			rebindSinglePhaseWriteOrderFixture(&descriptor, &target, &full)
			plan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v plan=%#v", err, plan)
			}
			if plan.MutationPermitted || plan.ExecutionSupported {
				t.Fatalf("refused staged profile crossed execution boundary: %#v", plan)
			}
		})
	}
}

func TestPlanSinglePhaseFullFlashWriteOrderRejectsExtentMapChanges(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RestoreTargetPlan)
		want string
	}{
		{
			name: "missing declared extent",
			edit: func(target *RestoreTargetPlan) {
				target.ResolvedWriteExtents = target.ResolvedWriteExtents[:len(target.ResolvedWriteExtents)-1]
			},
			want: "missing declared extent",
		},
		{
			name: "duplicate extent identity",
			edit: func(target *RestoreTargetPlan) {
				target.ResolvedWriteExtents[2].DescriptorIndex = 1
				target.ResolvedWriteExtents[2].LocationIndex = 0
			},
			want: "duplicate extent identity",
		},
		{
			name: "extra undeclared extent",
			edit: func(target *RestoreTargetPlan) {
				extra := ResolvedWriteExtent{
					DescriptorIndex:  99,
					LocationIndex:    0,
					Anchor:           "begin",
					TargetStartBlock: 2,
					TargetEndBlock:   3,
					TargetOffset:     8192,
					TargetLength:     4096,
					PayloadOffset:    8192,
					PayloadLength:    4096,
				}
				target.ResolvedWriteExtents = append(target.ResolvedWriteExtents[:1], append([]ResolvedWriteExtent{extra}, target.ResolvedWriteExtents[1:]...)...)
			},
			want: "not declared",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, target, full := validSinglePhaseWriteOrderFixture()
			test.edit(&target)
			rebindSinglePhaseWriteOrderFixture(&descriptor, &target, &full)
			plan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v plan=%#v", err, plan)
			}
		})
	}
}

func TestPlanSinglePhaseFullFlashWriteOrderRejectsPrerequisiteSubstitution(t *testing.T) {
	descriptor, target, full := validSinglePhaseWriteOrderFixture()
	target.DescriptorPlanSHA256 = strings.Repeat("d", 64)
	target.PlanSHA256 = restoreTargetPlanDigest(target)
	full.DescriptorPlanSHA256 = target.DescriptorPlanSHA256
	full.RestoreTargetPlanSHA256 = target.PlanSHA256
	full.PlanSHA256 = fullFlashValidationPlanDigest(full)
	plan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
	if err == nil || !strings.Contains(err.Error(), "descriptor or target-plan identity") {
		t.Fatalf("error=%v plan=%#v", err, plan)
	}
}

func TestValidateFullFlashWriteOrderPlanRejectsTampering(t *testing.T) {
	descriptor, target, full := validSinglePhaseWriteOrderFixture()
	plan, err := PlanSinglePhaseFullFlashWriteOrder(descriptor, target, full)
	if err != nil {
		t.Fatal(err)
	}
	plan.MutationPermitted = true
	if err := validateFullFlashWriteOrderPlan(plan); err == nil {
		t.Fatal("tampered mutation permission was accepted")
	}
}

func validSinglePhaseWriteOrderFixture() (DescriptorPlan, RestoreTargetPlan, FullFlashValidationPlan) {
	const (
		blockSize    = uint64(4096)
		sourceSize   = uint64(32768)
		payloadStart = uint64(8192)
		targetBlocks = uint64(8)
	)
	descriptor := DescriptorPlan{
		Schema:                    1,
		StoreMajorVersion:         1,
		StoreMinorVersion:         0,
		SourceFileSize:            sourceSize,
		ChunkSizeBytes:            blockSize,
		BlockSizeBytes:            blockSize,
		ValidationDescriptorOffset: 4096,
		WriteDescriptorOffset:      4096,
		WriteDescriptorEnd:         4160,
		PayloadOffset:              payloadStart,
		PayloadLength:              3 * blockSize,
		PayloadEnd:                 payloadStart + 3*blockSize,
		PayloadFileBytes:           sourceSize - payloadStart,
		TrailingFileBytes:          sourceSize - (payloadStart + 3*blockSize),
		TotalPayloadBlocks:         3,
		BeginningExtentBlocks:      6,
		EndingExtentBlocks:         1,
		MinimumTargetBlocks:        7,
		MinimumTargetBytes:         7 * blockSize,
		InitialTable:               PayloadTableRange{},
		FlashOnlyTable:             PayloadTableRange{},
		FinalTable:                 PayloadTableRange{BlockIndex: 0, BlockCount: 3, BlockEnd: 3},
		ValidationDescriptors:      nil,
		WriteDescriptors: []WriteDescriptor{
			{
				Index: 0, TableOffset: 4096, LocationCount: 1, BlockCount: 2,
				PayloadOffset: payloadStart, PayloadLength: 2 * blockSize,
				Locations: []DiskLocation{{Index: 0, AccessMethod: diskAccessBegin, Anchor: "begin", BlockIndex: 4, BlockEnd: 6}},
			},
			{
				Index: 1, TableOffset: 4112, LocationCount: 2, BlockCount: 1,
				PayloadOffset: payloadStart + 2*blockSize, PayloadLength: blockSize,
				Locations: []DiskLocation{
					{Index: 0, AccessMethod: diskAccessBegin, Anchor: "begin", BlockIndex: 0, BlockEnd: 1},
					{Index: 1, AccessMethod: diskAccessEnd, Anchor: "end", BlockIndex: 0, BlockEnd: 1},
				},
			},
		},
		DestinationOverlaps:       nil,
		HasDestinationOverlap:     false,
		TargetSizeBindingRequired: true,
		IntegrityAuthenticated:    false,
		ExecutionSupported:        false,
		Limitations:               []string{"test single-phase descriptor evidence"},
	}

	target := RestoreTargetPlan{
		Schema:                           restoreTargetPlanSchema,
		Mode:                             "ffu-restore",
		Destructive:                      true,
		SourceFileSize:                   sourceSize,
		AuthenticatedIntegrityPlanSHA256: strings.Repeat("a", 64),
		CatalogSHA256:                    strings.Repeat("b", 64),
		HashTableSHA256:                  strings.Repeat("c", 64),
		DevicePath:                       "/dev/test-ffu",
		ExpectedTargetIdentity:           "test-target-identity",
		TargetSizeBytes:                  targetBlocks * blockSize,
		LogicalSectorSizeBytes:           512,
		PhysicalSectorSizeBytes:          512,
		StoreBlockSizeBytes:              blockSize,
		TargetBlockCount:                 targetBlocks,
		MinimumTargetBytes:               descriptor.MinimumTargetBytes,
		ResolvedWriteExtents: []ResolvedWriteExtent{
			{DescriptorIndex: 1, LocationIndex: 0, Anchor: "begin", TargetStartBlock: 0, TargetEndBlock: 1, TargetOffset: 0, TargetLength: blockSize, PayloadOffset: payloadStart + 2*blockSize, PayloadLength: blockSize},
			{DescriptorIndex: 0, LocationIndex: 0, Anchor: "begin", TargetStartBlock: 4, TargetEndBlock: 6, TargetOffset: 4 * blockSize, TargetLength: 2 * blockSize, PayloadOffset: payloadStart, PayloadLength: 2 * blockSize},
			{DescriptorIndex: 1, LocationIndex: 1, Anchor: "end", TargetStartBlock: 7, TargetEndBlock: 8, TargetOffset: 7 * blockSize, TargetLength: blockSize, PayloadOffset: payloadStart + 2*blockSize, PayloadLength: blockSize},
		},
		ValidationDescriptorCount:    0,
		SourceIntegrityAuthenticated: true,
		TargetIdentityBound:          true,
		TargetGeometryBound:          true,
		DestinationMapResolved:       true,
		DestinationOverlap:           false,
		ValidationChecksRequired:     false,
		ValidationChecksResolved:     false,
		ConfirmationRequired:         true,
		ExecutionSupported:           false,
		Warnings:                     restoreTargetWarnings(),
		Limitations:                  restoreTargetLimitations(),
	}

	full := FullFlashValidationPlan{
		Schema:                           fullFlashValidationPlanSchema,
		Mode:                             "ffu-full-flash-restore",
		Destructive:                      true,
		SourceFileSize:                   sourceSize,
		AuthenticatedIntegrityPlanSHA256: target.AuthenticatedIntegrityPlanSHA256,
		CatalogSHA256:                    target.CatalogSHA256,
		HashTableSHA256:                  target.HashTableSHA256,
		DevicePath:                       target.DevicePath,
		ExpectedTargetIdentity:           target.ExpectedTargetIdentity,
		TargetSizeBytes:                  target.TargetSizeBytes,
		LogicalSectorSizeBytes:           target.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes:          target.PhysicalSectorSizeBytes,
		StoreBlockSizeBytes:              target.StoreBlockSizeBytes,
		TargetBlockCount:                 target.TargetBlockCount,
		StoreUpdateType:                  fullFlashUpdateType,
		ValidationDescriptorCount:        0,
		FullFlashUpdateConfirmed:         true,
		ValidationDescriptorsAbsent:      true,
		ValidationChecksResolved:         true,
		ConfirmationRequired:             true,
		ConfirmationPhrase:               expectedFullFlashConfirmationPhrase(target.DevicePath, target.TargetSizeBytes),
		ExecutionSupported:               false,
		Warnings:                         fullFlashValidationWarnings(),
		Limitations:                      fullFlashValidationLimitations(),
	}
	rebindSinglePhaseWriteOrderFixture(&descriptor, &target, &full)
	return descriptor, target, full
}

func rebindSinglePhaseWriteOrderFixture(descriptor *DescriptorPlan, target *RestoreTargetPlan, full *FullFlashValidationPlan) {
	descriptor.PlanSHA256 = descriptorPlanDigest(*descriptor)
	target.SourceFileSize = descriptor.SourceFileSize
	target.DescriptorPlanSHA256 = descriptor.PlanSHA256
	target.StoreBlockSizeBytes = descriptor.BlockSizeBytes
	target.MinimumTargetBytes = descriptor.MinimumTargetBytes
	target.WriteExtentCount = uint64(len(target.ResolvedWriteExtents))
	target.MutationBytes = 0
	for _, extent := range target.ResolvedWriteExtents {
		target.MutationBytes += extent.TargetLength
	}
	target.PlanSHA256 = restoreTargetPlanDigest(*target)

	full.SourceFileSize = target.SourceFileSize
	full.RestoreTargetPlanSHA256 = target.PlanSHA256
	full.AuthenticatedIntegrityPlanSHA256 = target.AuthenticatedIntegrityPlanSHA256
	full.DescriptorPlanSHA256 = descriptor.PlanSHA256
	full.CatalogSHA256 = target.CatalogSHA256
	full.HashTableSHA256 = target.HashTableSHA256
	full.DevicePath = target.DevicePath
	full.ExpectedTargetIdentity = target.ExpectedTargetIdentity
	full.TargetSizeBytes = target.TargetSizeBytes
	full.LogicalSectorSizeBytes = target.LogicalSectorSizeBytes
	full.PhysicalSectorSizeBytes = target.PhysicalSectorSizeBytes
	full.StoreBlockSizeBytes = target.StoreBlockSizeBytes
	full.TargetBlockCount = target.TargetBlockCount
	full.MutationBytes = target.MutationBytes
	full.ConfirmationPhrase = expectedFullFlashConfirmationPhrase(target.DevicePath, target.TargetSizeBytes)
	full.PlanSHA256 = fullFlashValidationPlanDigest(*full)
}
