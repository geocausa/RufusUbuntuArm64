//go:build linux

package ffu

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestAcquireAuthenticatedFullFlashSourceLease(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()

	session, err := AcquireAuthenticatedFullFlashSourceLease(
		context.Background(), fixture.file, fixture.identity, fixture.chain.activation,
		catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight,
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := session.Evidence()
	if err != nil {
		session.Close()
		t.Fatal(err)
	}
	if !evidence.KernelReadLeaseHeld || !evidence.SourceIdentityRevalidated || !evidence.FullFlashValidationReproduced || !evidence.TargetPreflightBound || evidence.FallbackAllowed || evidence.TargetAccessPermitted || evidence.ExecutionSupported {
		session.Close()
		t.Fatalf("source lease crossed or missed a boundary: %#v", evidence)
	}
	if evidence.SourceIdentity != fixture.identity || evidence.SourceFileSize != uint64(fixture.identity.Size) || evidence.FullFlashTargetPreflightSHA256 != fixture.preflight.PlanSHA256 || evidence.TargetDevicePath != fixture.request.DevicePath {
		session.Close()
		t.Fatalf("source lease lost prerequisite evidence: %#v", evidence)
	}
	if evidence.PlanSHA256 != fullFlashSourceLeaseEvidenceDigest(evidence) {
		session.Close()
		t.Fatal("source lease evidence digest mismatch")
	}
	if err := session.Check(); err != nil {
		session.Close()
		t.Fatal(err)
	}
	leaseContext, err := session.LeaseContext()
	if err != nil {
		session.Close()
		t.Fatal(err)
	}
	if leaseContext == nil || leaseContext.Err() != nil {
		session.Close()
		t.Fatalf("unexpected lease context: %v", leaseContext)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Check(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed session check error=%v", err)
	}
	writer, err := os.OpenFile(fixture.path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("writer after lease close: %v", err)
	}
	writer.Close()
}

func TestAuthenticatedFullFlashSourceLeaseIsDeterministic(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()
	first, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
	if err != nil {
		t.Fatal(err)
	}
	firstEvidence, err := first.Evidence()
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondEvidence, err := second.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if firstEvidence.PlanSHA256 != secondEvidence.PlanSHA256 {
		t.Fatal("identical source lease inputs produced different evidence")
	}
}

func TestAcquireAuthenticatedFullFlashSourceLeaseRejectsMismatch(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()

	wrongIdentity := fixture.identity
	wrongIdentity.Size++
	if session, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, wrongIdentity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight); err == nil {
		session.Close()
		t.Fatal("wrong source identity was accepted")
	}

	wrongPreflight := fixture.preflight
	wrongPreflight.FullFlashValidationPlanSHA256 = strings.Repeat("0", 64)
	wrongPreflight.PlanSHA256 = fullFlashTargetPreflightDigest(wrongPreflight)
	if session, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, wrongPreflight); err == nil || !strings.Contains(err.Error(), "does not reproduce") {
		if session != nil {
			session.Close()
		}
		t.Fatalf("preflight mismatch error=%v", err)
	}
}

func TestAcquireAuthenticatedFullFlashSourceLeaseRejectsNilAndCancelledInputs(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()
	var nilContext context.Context
	if session, err := AcquireAuthenticatedFullFlashSourceLease(nilContext, fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight); err == nil || !strings.Contains(err.Error(), "context is nil") {
		if session != nil {
			session.Close()
		}
		t.Fatalf("nil context error=%v", err)
	}
	if session, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), nil, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight); err == nil || !strings.Contains(err.Error(), "file is nil") {
		if session != nil {
			session.Close()
		}
		t.Fatalf("nil file error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session, err := AcquireAuthenticatedFullFlashSourceLease(ctx, fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight); !errors.Is(err, context.Canceled) {
		if session != nil {
			session.Close()
		}
		t.Fatalf("cancelled context error=%v", err)
	}
}

func TestValidateFullFlashSourceLeaseEvidenceRejectsTampering(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()
	session, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	evidence, err := session.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence.TargetDevicePath = "/dev/different"
	if err := validateFullFlashSourceLeaseEvidence(evidence); err == nil || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("tamper error=%v", err)
	}
}

type fullFlashSourceLeaseFixture struct {
	chain     catalogChainFixture
	policy    CatalogPublisherPolicy
	request   RestoreTargetRequest
	preflight FullFlashTargetPreflightPlan
	path      string
	file      *os.File
	identity  sourcefile.Identity
}

func newFullFlashSourceLeaseFixture(t testing.TB) fullFlashSourceLeaseFixture {
	t.Helper()
	chain := newFullFlashGateFixture(t, fullFlashUpdateType, false)
	policy := catalogPublisherTestPolicy(chain, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(chain.data), uint64(len(chain.data)))
	if err != nil {
		t.Fatal(err)
	}
	dev := device.BlockDevice{
		Name:       "test-ffu",
		Path:       "/dev/test-ffu",
		Type:       "disk",
		Size:       descriptor.MinimumTargetBytes,
		Vendor:     "RufusArm64",
		Model:      "source lease fixture",
		Transport:  "usb",
		Hotplug:    true,
		MajorMinor: "7:1",
		Serial:     "source-lease-serial",
		WWN:        "source-lease-wwn",
	}
	request := RestoreTargetRequest{
		DevicePath:              dev.Path,
		ExpectedTargetIdentity:  device.IdentityToken(dev),
		TargetSizeBytes:         dev.Size,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}
	_, validation, err := ResolveAuthenticatedSingleStoreV1FullFlash(context.Background(), bytes.NewReader(chain.data), uint64(len(chain.data)), chain.activation, catalogChainEvaluationTime, policy, request)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := buildFullFlashTargetPreflight(validation, dev, 0x701, 512, 512, true)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "source.ffu")
	if err := os.WriteFile(path, chain.data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := sourcefile.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	return fullFlashSourceLeaseFixture{
		chain: chain, policy: policy, request: request, preflight: preflight,
		path: path, file: file, identity: identity,
	}
}
