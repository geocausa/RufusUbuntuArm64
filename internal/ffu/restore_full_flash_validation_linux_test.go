//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestResolveAuthenticatedSingleStoreV1FullFlash(t *testing.T) {
	fixture := newFullFlashGateFixture(t, fullFlashUpdateType, false)
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

	target, plan, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.ValidationChecksRequired || target.ValidationChecksResolved || target.ValidationDescriptorCount != 0 {
		t.Fatalf("prerequisite target plan did not preserve the validation boundary: %#v", target)
	}
	if !plan.FullFlashUpdateConfirmed || !plan.ValidationDescriptorsAbsent || !plan.ValidationChecksResolved || plan.ExecutionSupported {
		t.Fatalf("full-flash gate did not resolve correctly: %#v", plan)
	}
	if plan.StoreUpdateType != fullFlashUpdateType || plan.ValidationDescriptorCount != 0 || plan.RestoreTargetPlanSHA256 != target.PlanSHA256 {
		t.Fatalf("full-flash evidence is inconsistent: %#v", plan)
	}
	if plan.DevicePath != request.DevicePath || plan.ExpectedTargetIdentity != request.ExpectedTargetIdentity || plan.TargetSizeBytes != request.TargetSizeBytes || plan.MutationBytes != target.MutationBytes {
		t.Fatalf("target binding was not preserved: %#v", plan)
	}
	phrase, err := FullFlashValidationConfirmationPhrase(plan)
	if err != nil {
		t.Fatal(err)
	}
	expectedPhrase := "RESTORE AUTHENTICATED FFU TO /dev/test-ffu SIZE " + strconv.FormatUint(request.TargetSizeBytes, 10) + " BYTES"
	if phrase != expectedPhrase || plan.ConfirmationPhrase != expectedPhrase {
		t.Fatalf("confirmation phrase=%q plan=%q", phrase, plan.ConfirmationPhrase)
	}
	if plan.PlanSHA256 != fullFlashValidationPlanDigest(plan) {
		t.Fatal("full-flash validation plan digest mismatch")
	}

	secondTarget, secondPlan, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondTarget.PlanSHA256 != target.PlanSHA256 || secondPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatal("identical source and target facts produced different full-flash evidence")
	}
}

func TestResolveAuthenticatedSingleStoreV1FullFlashRejectsOtherUpdateClasses(t *testing.T) {
	tests := []struct {
		name              string
		updateType        uint32
		includeValidation bool
		want              string
	}{
		{name: "partial", updateType: 1, includeValidation: true, want: "partial FFU update type 1"},
		{name: "unknown", updateType: 7, includeValidation: true, want: "unsupported FFU update type 7"},
		{name: "full with validation entries", updateType: 0, includeValidation: true, want: "full-flash FFU contains validation descriptors"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFullFlashGateFixture(t, test.updateType, test.includeValidation)
			policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
			_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
			if err != nil {
				t.Fatal(err)
			}
			request := RestoreTargetRequest{DevicePath: "/dev/test-ffu", ExpectedTargetIdentity: "test-target-identity", TargetSizeBytes: descriptor.MinimumTargetBytes, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512}
			target, plan, err := ResolveAuthenticatedSingleStoreV1FullFlash(context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v target=%#v plan=%#v", err, target, plan)
			}
			if plan.ValidationChecksResolved || plan.ExecutionSupported {
				t.Fatalf("refused update crossed validation or execution boundary: %#v", plan)
			}
		})
	}
}

func TestFullFlashValidationConfirmationRejectsTampering(t *testing.T) {
	fixture := newFullFlashGateFixture(t, fullFlashUpdateType, false)
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
	if err != nil {
		t.Fatal(err)
	}
	request := RestoreTargetRequest{DevicePath: "/dev/test-ffu", ExpectedTargetIdentity: "test-target-identity", TargetSizeBytes: descriptor.MinimumTargetBytes, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512}
	_, plan, err := ResolveAuthenticatedSingleStoreV1FullFlash(context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request)
	if err != nil {
		t.Fatal(err)
	}
	plan.ExpectedTargetIdentity = "different-target"
	if _, err := FullFlashValidationConfirmationPhrase(plan); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("error=%v", err)
	}
}

func TestResolveAuthenticatedSingleStoreV1FullFlashRejectsNilAndCancelledContext(t *testing.T) {
	fixture := newFullFlashGateFixture(t, fullFlashUpdateType, false)
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	request := RestoreTargetRequest{DevicePath: "/dev/test-ffu", ExpectedTargetIdentity: "test-target-identity", TargetSizeBytes: 1 << 20, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512}
	var nilContext context.Context
	if _, _, err := ResolveAuthenticatedSingleStoreV1FullFlash(nilContext, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ResolveAuthenticatedSingleStoreV1FullFlash(ctx, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
}

func newFullFlashGateFixture(t testing.TB, updateType uint32, includeValidation bool) catalogChainFixture {
	t.Helper()
	rootDER, root, rootKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x71, serial: 710, commonName: "RufusArm64 Full Flash Root", isCA: true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 1,
	})
	intermediateDER, intermediate, intermediateKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x72, serial: 720, commonName: "RufusArm64 Full Flash Intermediate", isCA: true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 0, maxPathLenZero: true,
		parent: root, parentKey: rootKey,
	})
	leafDER, leaf, leafKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x73, serial: 730, commonName: "RufusArm64 Full Flash Publisher", isCA: false,
		keyUsage: x509.KeyUsageDigitalSignature, extendedKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		parent: intermediate, parentKey: intermediateKey,
	})

	data := validV1PlanFixture()
	if !includeValidation {
		data = fullFlashNoValidationFixture(data)
	}
	binary.LittleEndian.PutUint32(data[8192:8196], updateType)
	table := fixtureHashTable(data)
	catalog := buildSignedCatalogDERWithCertificates(table, [][]byte{leafDER, intermediateDER}, leaf, leafKey)
	if 32+len(catalog)+len(table) >= 4096 {
		t.Fatalf("full-flash catalog fixture security area is too large: catalog=%d table=%d", len(catalog), len(table))
	}
	binary.LittleEndian.PutUint32(data[24:28], uint32(len(catalog)))
	binary.LittleEndian.PutUint32(data[28:32], uint32(len(table)))
	copy(data[32:32+len(catalog)], catalog)
	copy(data[32+len(catalog):32+len(catalog)+len(table)], table)

	activation := catalogChainActivationFixture(t, []catalogChainRoot{{id: "test.authenticode.root", der: rootDER, certificate: root}}, nil)
	return catalogChainFixture{
		data: data, activation: activation, leaf: leaf, intermediate: intermediate, root: root,
		intermediateFingerprint: certificateFingerprint(intermediate),
	}
}

func fullFlashNoValidationFixture(data []byte) []byte {
	result := append([]byte(nil), data...)
	const (
		storeOffset         = 8192
		validationOffset    = storeOffset + storeCommonHeaderBytes
		oldWriteOffset      = validationOffset + 16
		writeDescriptorSize = 40
	)
	copy(result[validationOffset:validationOffset+writeDescriptorSize], result[oldWriteOffset:oldWriteOffset+writeDescriptorSize])
	clear(result[validationOffset+writeDescriptorSize : oldWriteOffset+writeDescriptorSize])
	binary.LittleEndian.PutUint32(result[storeOffset+216:storeOffset+220], 0)
	binary.LittleEndian.PutUint32(result[storeOffset+220:storeOffset+224], 0)
	return result
}
