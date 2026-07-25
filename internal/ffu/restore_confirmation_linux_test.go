//go:build linux

package ffu

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/device"
)

func TestConfirmExclusiveFullFlashTarget(t *testing.T) {
	fixture := newFullFlashConfirmationFixture(t)
	defer fixture.close(t)

	expected := expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes)
	confirmation, err := ConfirmExclusiveFullFlashTarget(context.Background(), fixture.target, expected)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := confirmation.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.ConfirmationExactMatch || !evidence.ConfirmationConsumed || !evidence.SourceLeaseHeld || !evidence.TargetSessionHeld || !evidence.TargetAccessAcquired || evidence.GuardedUnmountPerformed || evidence.MutationPermitted || evidence.ExecutionSupported {
		t.Fatalf("confirmation crossed or missed a boundary: %#v", evidence)
	}
	if evidence.TargetSessionEvidenceSHA256 != fixture.targetEvidence.PlanSHA256 || evidence.SourceLeaseEvidenceSHA256 != fixture.targetEvidence.SourceLeaseEvidenceSHA256 || evidence.DevicePath != fixture.targetEvidence.DevicePath || evidence.ExpectedTargetIdentity != fixture.targetEvidence.ExpectedTargetIdentity || evidence.TargetSizeBytes != fixture.targetEvidence.TargetSizeBytes || evidence.MutationBytes != fixture.targetEvidence.MutationBytes {
		t.Fatalf("confirmation lost target-session binding: %#v", evidence)
	}
	if evidence.ExpectedConfirmationPhrase != expected || evidence.ConfirmationPhraseSHA256 == "" || evidence.PlanSHA256 != fullFlashConfirmationEvidenceDigest(evidence) {
		t.Fatalf("confirmation evidence is inconsistent: %#v", evidence)
	}
	if err := confirmation.Check(); err != nil {
		t.Fatal(err)
	}

	second, err := ConfirmExclusiveFullFlashTarget(context.Background(), fixture.target, expected)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, err := second.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	if secondEvidence.PlanSHA256 != evidence.PlanSHA256 {
		t.Fatal("identical live capabilities and phrase produced different confirmation evidence")
	}
}

func TestConfirmExclusiveFullFlashTargetRejectsNearMatches(t *testing.T) {
	fixture := newFullFlashConfirmationFixture(t)
	defer fixture.close(t)
	expected := expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes)

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "trailing newline", value: expected + "\n"},
		{name: "leading space", value: " " + expected},
		{name: "lowercase", value: strings.ToLower(expected)},
		{name: "wrong path", value: strings.Replace(expected, fixture.targetEvidence.DevicePath, "/dev/different", 1)},
		{name: "wrong size", value: expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes+1)},
		{name: "decimal padding", value: "RESTORE AUTHENTICATED FFU TO " + fixture.targetEvidence.DevicePath + " SIZE 0" + strconv.FormatUint(fixture.targetEvidence.TargetSizeBytes, 10) + " BYTES"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			confirmation, err := ConfirmExclusiveFullFlashTarget(context.Background(), fixture.target, test.value)
			if err == nil {
				t.Fatalf("near-match confirmation was accepted: %#v", confirmation)
			}
			if confirmation != nil {
				t.Fatal("failed confirmation returned a capability")
			}
		})
	}
}

func TestDestructiveConfirmationInvalidatesWithTargetSession(t *testing.T) {
	fixture := newFullFlashConfirmationFixture(t)
	defer fixture.source.Close()
	defer fixture.sourceFixture.file.Close()
	expected := expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes)
	confirmation, err := ConfirmExclusiveFullFlashTarget(context.Background(), fixture.target, expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := confirmation.Check(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("confirmation survived target close: %v", err)
	}
}

func TestConfirmExclusiveFullFlashTargetRejectsNilAndCancelledInputs(t *testing.T) {
	fixture := newFullFlashConfirmationFixture(t)
	defer fixture.close(t)
	expected := expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes)
	var nilContext context.Context
	if confirmation, err := ConfirmExclusiveFullFlashTarget(nilContext, fixture.target, expected); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context confirmation=%#v error=%v", confirmation, err)
	}
	if confirmation, err := ConfirmExclusiveFullFlashTarget(context.Background(), nil, expected); err == nil || !strings.Contains(err.Error(), "session is nil") {
		t.Fatalf("nil session confirmation=%#v error=%v", confirmation, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if confirmation, err := ConfirmExclusiveFullFlashTarget(ctx, fixture.target, expected); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context confirmation=%#v error=%v", confirmation, err)
	}
}

func TestValidateFullFlashConfirmationEvidenceRejectsTampering(t *testing.T) {
	fixture := newFullFlashConfirmationFixture(t)
	defer fixture.close(t)
	expected := expectedFullFlashConfirmationPhrase(fixture.targetEvidence.DevicePath, fixture.targetEvidence.TargetSizeBytes)
	confirmation, err := ConfirmExclusiveFullFlashTarget(context.Background(), fixture.target, expected)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := confirmation.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence.TargetSizeBytes++
	if err := validateFullFlashConfirmationEvidence(evidence); err == nil {
		t.Fatal("tampered confirmation evidence was accepted")
	}
}

type fullFlashConfirmationFixture struct {
	sourceFixture fullFlashSourceLeaseFixture
	source        *FullFlashSourceLease
	target        *FullFlashTargetSession
	targetEvidence FullFlashTargetSessionEvidence
	targetPath    string
	original      []byte
}

func newFullFlashConfirmationFixture(t testing.TB) fullFlashConfirmationFixture {
	t.Helper()
	sourceFixture := newFullFlashSourceLeaseFixture(t)
	source, err := AcquireAuthenticatedFullFlashSourceLease(
		context.Background(), sourceFixture.file, sourceFixture.identity, sourceFixture.chain.activation,
		catalogChainEvaluationTime, sourceFixture.policy, sourceFixture.request, sourceFixture.preflight,
	)
	if err != nil {
		sourceFixture.file.Close()
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.bin")
	original := bytes.Repeat([]byte{0xa5}, 8192)
	if err := os.WriteFile(targetPath, original, 0o600); err != nil {
		source.Close()
		sourceFixture.file.Close()
		t.Fatal(err)
	}
	dev := exclusiveTargetSessionTestDevice(sourceFixture.preflight)
	ops := fullFlashTargetOpenOps{
		openTarget: func(string) (*os.File, error) { return os.OpenFile(targetPath, os.O_RDWR, 0) },
		verifyOpenTarget: func(file *os.File, expectedID, expectedSize uint64) error {
			if file == nil || expectedID != sourceFixture.preflight.KernelDeviceID || expectedSize != sourceFixture.preflight.TargetSizeBytes {
				return errors.New("unexpected target verification inputs")
			}
			return nil
		},
		revalidateTarget: func(string, uint64) (device.BlockDevice, uint64, error) {
			return dev, sourceFixture.preflight.KernelDeviceID, nil
		},
		readSectorGeometry: func(string) (uint64, uint64, error) {
			return sourceFixture.preflight.LogicalSectorSizeBytes, sourceFixture.preflight.PhysicalSectorSizeBytes, nil
		},
		ensureSourceOutside: func(*os.File, device.BlockDevice) error { return nil },
	}
	target, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), source, sourceFixture.preflight, ops)
	if err != nil {
		source.Close()
		sourceFixture.file.Close()
		t.Fatal(err)
	}
	targetEvidence, err := target.Evidence()
	if err != nil {
		target.Close()
		source.Close()
		sourceFixture.file.Close()
		t.Fatal(err)
	}
	return fullFlashConfirmationFixture{
		sourceFixture: sourceFixture,
		source: source,
		target: target,
		targetEvidence: targetEvidence,
		targetPath: targetPath,
		original: original,
	}
}

func (fixture *fullFlashConfirmationFixture) close(t testing.TB) {
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
	if fixture.sourceFixture.file != nil {
		if err := fixture.sourceFixture.file.Close(); err != nil {
			t.Error(err)
		}
	}
	actual, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(actual, fixture.original) {
		t.Error("destructive-confirmation boundary modified target bytes")
	}
}
