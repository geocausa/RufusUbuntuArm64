//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestAuthorizeSinglePhaseFullFlashMutation(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)

	authorization, err := AuthorizeSinglePhaseFullFlashMutation(
		context.Background(), fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan,
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := authorization.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.ConfirmationSatisfied || !evidence.SourceLeaseHeld || !evidence.TargetSessionHeld || !evidence.TargetAccessAcquired || !evidence.SinglePhaseWriteOrderResolved || evidence.StagedGPTProfileAllowed || evidence.GuardedUnmountPerformed || !evidence.OneShotExecutionRequired || evidence.AuthorizationConsumed || !evidence.MutationPermitted || evidence.ExecutionSupported {
		t.Fatalf("mutation authorization crossed or missed a boundary: %#v", evidence)
	}
	if evidence.FullFlashValidationPlanSHA256 != fixture.fullPlan.PlanSHA256 || evidence.RestoreTargetPlanSHA256 != fixture.targetPlan.PlanSHA256 || evidence.DescriptorPlanSHA256 != fixture.descriptor.PlanSHA256 || evidence.AuthenticatedIntegritySHA256 != fixture.fullPlan.AuthenticatedIntegrityPlanSHA256 {
		t.Fatalf("mutation authorization lost prerequisite binding: %#v", evidence)
	}
	if evidence.DevicePath != fixture.fullPlan.DevicePath || evidence.ExpectedTargetIdentity != fixture.fullPlan.ExpectedTargetIdentity || evidence.TargetSizeBytes != fixture.fullPlan.TargetSizeBytes || evidence.MutationBytes != fixture.fullPlan.MutationBytes || evidence.OperationCount != 3 {
		t.Fatalf("mutation authorization lost target or operation scope: %#v", evidence)
	}
	if evidence.PlanSHA256 != fullFlashMutationAuthorizationEvidenceDigest(evidence) {
		t.Fatal("mutation authorization evidence digest mismatch")
	}
	if err := authorization.Check(); err != nil {
		t.Fatal(err)
	}

	second, err := AuthorizeSinglePhaseFullFlashMutation(
		context.Background(), fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, err := second.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if secondEvidence.PlanSHA256 != evidence.PlanSHA256 {
		t.Fatal("identical live capabilities and plans produced different mutation authorization evidence")
	}
}

func TestAuthorizeSinglePhaseFullFlashMutationRejectsStagedProfile(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	descriptor := fixture.descriptor
	target := fixture.targetPlan
	full := fixture.fullPlan
	descriptor.InitialTable = PayloadTableRange{BlockIndex: 0, BlockCount: 1, BlockEnd: 1}
	rebindMutationAuthorizationPlans(&descriptor, &target, &full)
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), fixture.confirmation, descriptor, target, full)
	if err == nil || !strings.Contains(err.Error(), "staged GPT") {
		t.Fatalf("error=%v authorization=%#v", err, authorization)
	}
	if authorization != nil {
		t.Fatal("refused staged profile returned a mutation capability")
	}
}

func TestAuthorizeSinglePhaseFullFlashMutationRejectsTargetSubstitution(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	descriptor := fixture.descriptor
	target := fixture.targetPlan
	full := fixture.fullPlan
	target.ExpectedTargetIdentity = strings.Repeat("d", 64)
	full.ExpectedTargetIdentity = target.ExpectedTargetIdentity
	rebindMutationAuthorizationPlans(&descriptor, &target, &full)
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), fixture.confirmation, descriptor, target, full)
	if err == nil || !strings.Contains(err.Error(), "does not bind the supplied full-flash prerequisites") {
		t.Fatalf("error=%v authorization=%#v", err, authorization)
	}
	if authorization != nil {
		t.Fatal("substituted target returned a mutation capability")
	}
}

func TestMutationAuthorizationInvalidatesWithTargetSession(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.source.Close()
	defer fixture.sourceFile.Close()
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.target.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.target = nil
	if err := authorization.Check(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("mutation authorization survived target close: %v", err)
	}
	actual, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, fixture.original) {
		t.Fatal("mutation authorization modified target bytes")
	}
}

func TestAuthorizeSinglePhaseFullFlashMutationRejectsNilAndCancelledInputs(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	var nilContext context.Context
	if authorization, err := AuthorizeSinglePhaseFullFlashMutation(nilContext, fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context authorization=%#v error=%v", authorization, err)
	}
	if authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), nil, fixture.descriptor, fixture.targetPlan, fixture.fullPlan); err == nil || !strings.Contains(err.Error(), "capability is nil") {
		t.Fatalf("nil confirmation authorization=%#v error=%v", authorization, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if authorization, err := AuthorizeSinglePhaseFullFlashMutation(ctx, fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context authorization=%#v error=%v", authorization, err)
	}
}

func TestValidateFullFlashMutationAuthorizationEvidenceRejectsTampering(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := authorization.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence.AuthorizationConsumed = true
	if err := validateFullFlashMutationAuthorizationEvidence(evidence); err == nil {
		t.Fatal("tampered consumed state was accepted")
	}
}

type singlePhaseMutationAuthorizationFixture struct {
	descriptor   DescriptorPlan
	targetPlan   RestoreTargetPlan
	fullPlan     FullFlashValidationPlan
	source       *FullFlashSourceLease
	sourceFile   *os.File
	target       *FullFlashTargetSession
	confirmation *FullFlashDestructiveConfirmation
	targetPath   string
	original     []byte
}

func newSinglePhaseMutationAuthorizationFixture(t testing.TB) singlePhaseMutationAuthorizationFixture {
	t.Helper()
	chain := newSinglePhaseFullFlashGateFixture(t)
	policy := catalogPublisherTestPolicy(chain, catalogPublisherIdentityCertificate)
	descriptorInspection, descriptor, err := PlanSingleStoreV1(bytes.NewReader(chain.data), uint64(len(chain.data)))
	if err != nil {
		t.Fatal(err)
	}
	if descriptorInspection.Store.UpdateType != fullFlashUpdateType {
		t.Fatal("single-phase fixture is not full flash")
	}
	dev := device.BlockDevice{
		Name:       "test-ffu",
		Path:       "/dev/test-ffu",
		Type:       "disk",
		Size:       descriptor.MinimumTargetBytes,
		Vendor:     "RufusArm64",
		Model:      "single-phase mutation fixture",
		Transport:  "usb",
		Hotplug:    true,
		MajorMinor: "7:2",
		Serial:     "single-phase-mutation-serial",
		WWN:        "single-phase-mutation-wwn",
	}
	request := RestoreTargetRequest{
		DevicePath:              dev.Path,
		ExpectedTargetIdentity:  device.IdentityToken(dev),
		TargetSizeBytes:         dev.Size,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}
	targetPlan, fullPlan, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		context.Background(), bytes.NewReader(chain.data), uint64(len(chain.data)), chain.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := buildFullFlashTargetPreflight(fullPlan, dev, 0x702, 512, 512, true)
	if err != nil {
		t.Fatal(err)
	}

	sourcePath := filepath.Join(t.TempDir(), "source.ffu")
	if err := os.WriteFile(sourcePath, chain.data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := sourcefile.Inspect(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	sourceFile, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	source, err := AcquireAuthenticatedFullFlashSourceLease(
		context.Background(), sourceFile, identity, chain.activation, catalogChainEvaluationTime, policy, request, preflight,
	)
	if err != nil {
		sourceFile.Close()
		t.Fatal(err)
	}

	targetPath := filepath.Join(t.TempDir(), "target.bin")
	original := bytes.Repeat([]byte{0xa5}, int(request.TargetSizeBytes))
	if err := os.WriteFile(targetPath, original, 0o600); err != nil {
		source.Close()
		sourceFile.Close()
		t.Fatal(err)
	}
	ops := fullFlashTargetOpenOps{
		openTarget: func(string) (*os.File, error) { return os.OpenFile(targetPath, os.O_RDWR, 0) },
		verifyOpenTarget: func(file *os.File, expectedID, expectedSize uint64) error {
			if file == nil || expectedID != preflight.KernelDeviceID || expectedSize != preflight.TargetSizeBytes {
				return errors.New("unexpected target verification inputs")
			}
			return nil
		},
		revalidateTarget: func(string, uint64) (device.BlockDevice, uint64, error) {
			return dev, preflight.KernelDeviceID, nil
		},
		readSectorGeometry: func(string) (uint64, uint64, error) {
			return preflight.LogicalSectorSizeBytes, preflight.PhysicalSectorSizeBytes, nil
		},
		ensureSourceOutside: func(*os.File, device.BlockDevice) error { return nil },
	}
	target, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), source, preflight, ops)
	if err != nil {
		source.Close()
		sourceFile.Close()
		t.Fatal(err)
	}
	targetEvidence, err := target.Evidence()
	if err != nil {
		target.Close()
		source.Close()
		sourceFile.Close()
		t.Fatal(err)
	}
	confirmation, err := ConfirmExclusiveFullFlashTarget(
		context.Background(), target, expectedFullFlashConfirmationPhrase(targetEvidence.DevicePath, targetEvidence.TargetSizeBytes),
	)
	if err != nil {
		target.Close()
		source.Close()
		sourceFile.Close()
		t.Fatal(err)
	}
	return singlePhaseMutationAuthorizationFixture{
		descriptor: descriptor, targetPlan: targetPlan, fullPlan: fullPlan,
		source: source, sourceFile: sourceFile, target: target, confirmation: confirmation,
		targetPath: targetPath, original: original,
	}
}

func (fixture *singlePhaseMutationAuthorizationFixture) close(t testing.TB) {
	t.Helper()
	if fixture.target != nil {
		if err := fixture.target.Close(); err != nil {
			t.Error(err)
		}
	}
	if fixture.source != nil {
		if err := fixture.source.Close(); err != nil {
			t.Error(err)
		}
	}
	if fixture.sourceFile != nil {
		if err := fixture.sourceFile.Close(); err != nil {
			t.Error(err)
		}
	}
	actual, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(actual, fixture.original) {
		t.Error("sealed mutation authorization modified target bytes")
	}
}

func newSinglePhaseFullFlashGateFixture(t testing.TB) catalogChainFixture {
	t.Helper()
	rootDER, root, rootKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x81, serial: 810, commonName: "RufusArm64 Single Phase Root", isCA: true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 1,
	})
	intermediateDER, intermediate, intermediateKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x82, serial: 820, commonName: "RufusArm64 Single Phase Intermediate", isCA: true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 0, maxPathLenZero: true,
		parent: root, parentKey: rootKey,
	})
	leafDER, leaf, leafKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x83, serial: 830, commonName: "RufusArm64 Single Phase Publisher", isCA: false,
		keyUsage: x509.KeyUsageDigitalSignature, extendedKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		parent: intermediate, parentKey: intermediateKey,
	})

	data := fullFlashNoValidationFixture(validV1PlanFixture())
	const storeOffset = 8192
	binary.LittleEndian.PutUint32(data[storeOffset:storeOffset+4], fullFlashUpdateType)
	binary.LittleEndian.PutUint32(data[storeOffset+224:storeOffset+228], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+228:storeOffset+232], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+232:storeOffset+236], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+236:storeOffset+240], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+240:storeOffset+244], 0)
	binary.LittleEndian.PutUint32(data[storeOffset+244:storeOffset+248], 3)
	table := fixtureHashTable(data)
	catalog := buildSignedCatalogDERWithCertificates(table, [][]byte{leafDER, intermediateDER}, leaf, leafKey)
	if 32+len(catalog)+len(table) >= 4096 {
		t.Fatalf("single-phase catalog fixture security area is too large: catalog=%d table=%d", len(catalog), len(table))
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

func rebindMutationAuthorizationPlans(descriptor *DescriptorPlan, target *RestoreTargetPlan, full *FullFlashValidationPlan) {
	descriptor.PlanSHA256 = descriptorPlanDigest(*descriptor)
	target.DescriptorPlanSHA256 = descriptor.PlanSHA256
	target.PlanSHA256 = restoreTargetPlanDigest(*target)
	full.DescriptorPlanSHA256 = descriptor.PlanSHA256
	full.RestoreTargetPlanSHA256 = target.PlanSHA256
	full.PlanSHA256 = fullFlashValidationPlanDigest(*full)
}
