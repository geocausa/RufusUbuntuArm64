//go:build linux

package ffu

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestBindAuthenticatedSingleStoreV1TargetResolvesExactTarget(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
	if err != nil {
		t.Fatal(err)
	}
	request := RestoreTargetRequest{
		DevicePath:              "/dev/test-ffu",
		ExpectedTargetIdentity:  "test-target-identity",
		TargetSizeBytes:         descriptor.MinimumTargetBytes,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}

	inspection, returnedDescriptor, hashPlan, verification, catalogPlan, integrityPlan, targetPlan, err := BindAuthenticatedSingleStoreV1Target(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || returnedDescriptor.PlanSHA256 != descriptor.PlanSHA256 {
		t.Fatalf("unexpected source plan: inspection=%#v descriptor=%#v", inspection, returnedDescriptor)
	}
	if !hashPlan.HashTableCatalogAuthenticated || !hashPlan.ContentMatchesHashTable || !verification.IntegrityAuthenticated || !catalogPlan.HashTableCatalogAuthenticated || !integrityPlan.IntegrityAuthenticated {
		t.Fatalf("source authentication did not complete before target binding")
	}
	if !targetPlan.SourceIntegrityAuthenticated || !targetPlan.TargetIdentityBound || !targetPlan.TargetGeometryBound || !targetPlan.DestinationMapResolved {
		t.Fatalf("target plan did not complete: %#v", targetPlan)
	}
	if targetPlan.DestinationOverlap || targetPlan.ValidationChecksResolved || targetPlan.ExecutionSupported || !targetPlan.ConfirmationRequired {
		t.Fatalf("target plan crossed a later boundary: %#v", targetPlan)
	}
	if targetPlan.DevicePath != request.DevicePath || targetPlan.ExpectedTargetIdentity != request.ExpectedTargetIdentity || targetPlan.TargetSizeBytes != request.TargetSizeBytes || targetPlan.TargetBlockCount != request.TargetSizeBytes/descriptor.BlockSizeBytes {
		t.Fatalf("target identity or geometry is not bound: %#v", targetPlan)
	}
	if targetPlan.AuthenticatedIntegrityPlanSHA256 != integrityPlan.PlanSHA256 || targetPlan.DescriptorPlanSHA256 != descriptor.PlanSHA256 || targetPlan.CatalogSHA256 != integrityPlan.CatalogSHA256 || targetPlan.HashTableSHA256 != integrityPlan.HashTableSHA256 {
		t.Fatalf("target plan is not linked to authenticated source evidence: %#v", targetPlan)
	}
	if targetPlan.WriteExtentCount == 0 || targetPlan.WriteExtentCount != uint64(len(targetPlan.ResolvedWriteExtents)) || targetPlan.MutationBytes == 0 {
		t.Fatalf("target extent accounting is empty or inconsistent: %#v", targetPlan)
	}
	for index, extent := range targetPlan.ResolvedWriteExtents {
		if extent.TargetEndBlock > targetPlan.TargetBlockCount || extent.TargetOffset+extent.TargetLength > targetPlan.TargetSizeBytes || extent.TargetLength != extent.PayloadLength {
			t.Fatalf("extent %d is out of bounds: %#v", index, extent)
		}
		if index != 0 && extent.TargetStartBlock < targetPlan.ResolvedWriteExtents[index-1].TargetEndBlock {
			t.Fatalf("extents overlap: %#v", targetPlan.ResolvedWriteExtents)
		}
	}
	phrase, err := RestoreTargetConfirmationPhrase(targetPlan)
	if err != nil {
		t.Fatal(err)
	}
	if phrase != "RESTORE AUTHENTICATED FFU TO /dev/test-ffu SIZE "+strconv.FormatUint(request.TargetSizeBytes, 10)+" BYTES" {
		t.Fatalf("confirmation phrase=%q", phrase)
	}
	if targetPlan.PlanSHA256 != restoreTargetPlanDigest(targetPlan) {
		t.Fatal("target plan digest mismatch")
	}

	_, _, _, _, _, secondIntegrity, secondPlan, err := BindAuthenticatedSingleStoreV1Target(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondIntegrity.PlanSHA256 != integrityPlan.PlanSHA256 || secondPlan.PlanSHA256 != targetPlan.PlanSHA256 {
		t.Fatal("identical source and target facts produced different evidence")
	}
}

func TestBindAuthenticatedSingleStoreV1TargetRejectsInvalidTargetFacts(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
	if err != nil {
		t.Fatal(err)
	}
	valid := RestoreTargetRequest{
		DevicePath:              "/dev/test-ffu",
		ExpectedTargetIdentity:  "test-target-identity",
		TargetSizeBytes:         descriptor.MinimumTargetBytes,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}
	tests := []struct {
		name    string
		mutate  func(*RestoreTargetRequest)
		message string
	}{
		{name: "relative path", mutate: func(request *RestoreTargetRequest) { request.DevicePath = "dev/test" }, message: "canonical absolute path"},
		{name: "empty identity", mutate: func(request *RestoreTargetRequest) { request.ExpectedTargetIdentity = "" }, message: "identity"},
		{name: "small target", mutate: func(request *RestoreTargetRequest) {
			request.TargetSizeBytes = descriptor.MinimumTargetBytes - descriptor.BlockSizeBytes
		}, message: "smaller than required"},
		{name: "unaligned target", mutate: func(request *RestoreTargetRequest) { request.TargetSizeBytes++ }, message: "not aligned"},
		{name: "bad logical sector", mutate: func(request *RestoreTargetRequest) { request.LogicalSectorSizeBytes = 1000 }, message: "sector geometry"},
		{name: "physical below logical", mutate: func(request *RestoreTargetRequest) {
			request.LogicalSectorSizeBytes = 4096
			request.PhysicalSectorSizeBytes = 512
		}, message: "sector geometry"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			_, _, _, _, _, _, plan, err := BindAuthenticatedSingleStoreV1Target(
				context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
			)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error=%v plan=%#v", err, plan)
			}
			if plan.TargetIdentityBound || plan.ExecutionSupported {
				t.Fatalf("invalid request crossed target boundary: %#v", plan)
			}
		})
	}
}

func TestResolveRestoreWriteExtentsResolvesBeginAndEnd(t *testing.T) {
	descriptor := DescriptorPlan{
		BlockSizeBytes: 4096,
		WriteDescriptors: []WriteDescriptor{
			{
				Index:         0,
				BlockCount:    2,
				PayloadOffset: 1000,
				PayloadLength: 8192,
				Locations:     []DiskLocation{{Index: 0, Anchor: "begin", BlockIndex: 2, BlockEnd: 4}},
			},
			{
				Index:         1,
				BlockCount:    2,
				PayloadOffset: 9192,
				PayloadLength: 8192,
				Locations:     []DiskLocation{{Index: 0, Anchor: "end", BlockIndex: 1, BlockEnd: 3}},
			},
		},
	}
	extents, mutationBytes, err := resolveRestoreWriteExtents(descriptor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || mutationBytes != 16384 {
		t.Fatalf("extents=%#v mutation=%d", extents, mutationBytes)
	}
	if extents[0].TargetStartBlock != 2 || extents[0].TargetEndBlock != 4 || extents[0].TargetOffset != 8192 {
		t.Fatalf("begin extent=%#v", extents[0])
	}
	if extents[1].TargetStartBlock != 7 || extents[1].TargetEndBlock != 9 || extents[1].TargetOffset != 28672 {
		t.Fatalf("end extent=%#v", extents[1])
	}
}

func TestResolveRestoreWriteExtentsRejectsTargetSpecificOverlap(t *testing.T) {
	descriptor := DescriptorPlan{
		BlockSizeBytes: 4096,
		WriteDescriptors: []WriteDescriptor{
			{Index: 0, BlockCount: 2, PayloadOffset: 0, PayloadLength: 8192, Locations: []DiskLocation{{Index: 0, Anchor: "begin", BlockIndex: 6, BlockEnd: 8}}},
			{Index: 1, BlockCount: 2, PayloadOffset: 8192, PayloadLength: 8192, Locations: []DiskLocation{{Index: 0, Anchor: "end", BlockIndex: 1, BlockEnd: 3}}},
		},
	}
	_, _, err := resolveRestoreWriteExtents(descriptor, 10)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("error=%v", err)
	}
}

func TestRestoreTargetConfirmationRejectsTamperedPlan(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
	if err != nil {
		t.Fatal(err)
	}
	request := RestoreTargetRequest{DevicePath: "/dev/test-ffu", ExpectedTargetIdentity: "test-target-identity", TargetSizeBytes: descriptor.MinimumTargetBytes, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512}
	_, _, _, _, _, _, plan, err := BindAuthenticatedSingleStoreV1Target(context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request)
	if err != nil {
		t.Fatal(err)
	}
	plan.ExpectedTargetIdentity = "different-target"
	if _, err := RestoreTargetConfirmationPhrase(plan); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("error=%v", err)
	}
}

func TestBindAuthenticatedSingleStoreV1TargetRejectsNilAndCancelledContext(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	request := RestoreTargetRequest{DevicePath: "/dev/test-ffu", ExpectedTargetIdentity: "test-target-identity", TargetSizeBytes: 1 << 20, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512}
	var nilContext context.Context
	if _, _, _, _, _, _, _, err := BindAuthenticatedSingleStoreV1Target(nilContext, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, _, _, _, err := BindAuthenticatedSingleStoreV1Target(ctx, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
}
