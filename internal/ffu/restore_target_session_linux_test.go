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
)

func TestAcquireExclusiveFullFlashTargetWithOps(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()
	sourceLease, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceLease.Close()

	targetPath := filepath.Join(t.TempDir(), "target.bin")
	original := bytes.Repeat([]byte{0x5a}, 8192)
	if err := os.WriteFile(targetPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	dev := exclusiveTargetSessionTestDevice(fixture.preflight)
	verifyCalls := 0
	ops := fullFlashTargetOpenOps{
		openTarget: func(path string) (*os.File, error) {
			if path != fixture.preflight.DevicePath {
				t.Fatalf("open path=%q", path)
			}
			return os.OpenFile(targetPath, os.O_RDWR, 0)
		},
		verifyOpenTarget: func(file *os.File, expectedID, expectedSize uint64) error {
			verifyCalls++
			if file == nil || expectedID != fixture.preflight.KernelDeviceID || expectedSize != fixture.preflight.TargetSizeBytes {
				return errors.New("unexpected verification inputs")
			}
			return nil
		},
		revalidateTarget: func(path string, expectedID uint64) (device.BlockDevice, uint64, error) {
			if path != fixture.preflight.DevicePath || expectedID != fixture.preflight.KernelDeviceID {
				return device.BlockDevice{}, 0, errors.New("unexpected revalidation inputs")
			}
			return dev, fixture.preflight.KernelDeviceID, nil
		},
		readSectorGeometry: func(name string) (uint64, uint64, error) {
			if name != dev.Name {
				return 0, 0, errors.New("unexpected device name")
			}
			return fixture.preflight.LogicalSectorSizeBytes, fixture.preflight.PhysicalSectorSizeBytes, nil
		},
		ensureSourceOutside: func(source *os.File, target device.BlockDevice) error {
			if source != fixture.file || target.Path != dev.Path {
				return errors.New("unexpected source/target relationship inputs")
			}
			return nil
		},
	}

	session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, fixture.preflight, ops)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := session.Evidence()
	if err != nil {
		session.Close()
		t.Fatal(err)
	}
	if !evidence.SourceLeaseHeld || !evidence.TargetOpenedReadWrite || !evidence.KernelExclusiveOpen || !evidence.NoFollowOpen || !evidence.MountedTargetsAbsent || evidence.GuardedUnmountPerformed || !evidence.TargetDescriptorVerified || !evidence.TargetPolicyRevalidated || !evidence.TargetGeometryRevalidated || !evidence.SourceOutsideTargetConfirmed || evidence.FixedDiskOverrideAllowed || !evidence.TargetAccessAcquired || evidence.MutationPermitted || evidence.ExecutionSupported {
		session.Close()
		t.Fatalf("target session crossed or missed a boundary: %#v", evidence)
	}
	if evidence.SourceLeaseEvidenceSHA256 == "" || evidence.FullFlashTargetPreflightSHA256 != fixture.preflight.PlanSHA256 || evidence.ExpectedTargetIdentity != fixture.preflight.ExpectedTargetIdentity || evidence.ExpectedKernelDeviceID != fixture.preflight.KernelDeviceID || evidence.ObservedKernelDeviceID != fixture.preflight.KernelDeviceID {
		session.Close()
		t.Fatalf("target session lost prerequisite evidence: %#v", evidence)
	}
	if evidence.PlanSHA256 != fullFlashTargetSessionEvidenceDigest(evidence) {
		session.Close()
		t.Fatal("target session evidence digest mismatch")
	}
	if err := session.Check(); err != nil {
		session.Close()
		t.Fatal(err)
	}
	if verifyCalls < 3 {
		session.Close()
		t.Fatalf("target descriptor verified only %d times", verifyCalls)
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
	actual, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, original) {
		t.Fatal("exclusive target acquisition modified target bytes")
	}
}

func TestAcquireExclusiveFullFlashTargetRejectsUnsafeStates(t *testing.T) {
	newSessionFixture := func(t *testing.T) (fullFlashSourceLeaseFixture, *FullFlashSourceLease, device.BlockDevice, fullFlashTargetOpenOps) {
		t.Helper()
		fixture := newFullFlashSourceLeaseFixture(t)
		sourceLease, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
		if err != nil {
			fixture.file.Close()
			t.Fatal(err)
		}
		dev := exclusiveTargetSessionTestDevice(fixture.preflight)
		targetPath := filepath.Join(t.TempDir(), "target.bin")
		if err := os.WriteFile(targetPath, make([]byte, 4096), 0o600); err != nil {
			sourceLease.Close()
			fixture.file.Close()
			t.Fatal(err)
		}
		ops := fullFlashTargetOpenOps{
			openTarget:       func(string) (*os.File, error) { return os.OpenFile(targetPath, os.O_RDWR, 0) },
			verifyOpenTarget: func(*os.File, uint64, uint64) error { return nil },
			revalidateTarget: func(string, uint64) (device.BlockDevice, uint64, error) {
				return dev, fixture.preflight.KernelDeviceID, nil
			},
			readSectorGeometry: func(string) (uint64, uint64, error) {
				return fixture.preflight.LogicalSectorSizeBytes, fixture.preflight.PhysicalSectorSizeBytes, nil
			},
			ensureSourceOutside: func(*os.File, device.BlockDevice) error { return nil },
		}
		return fixture, sourceLease, dev, ops
	}

	t.Run("mounted preflight", func(t *testing.T) {
		fixture, sourceLease, _, ops := newSessionFixture(t)
		defer fixture.file.Close()
		defer sourceLease.Close()
		preflight := fixture.preflight
		preflight.MountedTargets = []FullFlashTargetMount{{DevicePath: "/dev/test-ffu1", Mountpoint: "/media/user/FFU"}}
		preflight.UnmountRequired = true
		preflight.PlanSHA256 = fullFlashTargetPreflightDigest(preflight)
		if session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, preflight, ops); err == nil || !strings.Contains(err.Error(), "fully unmounted") {
			if session != nil {
				session.Close()
			}
			t.Fatalf("mounted preflight error=%v", err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*fullFlashTargetOpenOps, *device.BlockDevice, FullFlashTargetPreflightPlan)
		want   string
	}{
		{name: "open failure", mutate: func(ops *fullFlashTargetOpenOps, _ *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			ops.openTarget = func(string) (*os.File, error) { return nil, errors.New("open denied") }
		}, want: "open denied"},
		{name: "descriptor verification", mutate: func(ops *fullFlashTargetOpenOps, _ *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			ops.verifyOpenTarget = func(*os.File, uint64, uint64) error { return errors.New("wrong descriptor") }
		}, want: "wrong descriptor"},
		{name: "kernel identity", mutate: func(ops *fullFlashTargetOpenOps, dev *device.BlockDevice, preflight FullFlashTargetPreflightPlan) {
			ops.revalidateTarget = func(string, uint64) (device.BlockDevice, uint64, error) {
				return *dev, preflight.KernelDeviceID + 1, nil
			}
		}, want: "kernel identity changed"},
		{name: "target identity", mutate: func(_ *fullFlashTargetOpenOps, dev *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			dev.MajorMinor = "7:9"
		}, want: "target identity changed"},
		{name: "capacity", mutate: func(_ *fullFlashTargetOpenOps, dev *device.BlockDevice, _ FullFlashTargetPreflightPlan) { dev.Size++ }, want: "whole-disk metadata changed"},
		{name: "became mounted", mutate: func(_ *fullFlashTargetOpenOps, dev *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			dev.Children = []device.BlockDevice{{Path: "/dev/test-ffu1", Type: "part", Mountpoints: []string{"/media/user/FFU"}}}
		}, want: "became mounted"},
		{name: "geometry", mutate: func(ops *fullFlashTargetOpenOps, _ *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			ops.readSectorGeometry = func(string) (uint64, uint64, error) { return 4096, 4096, nil }
		}, want: "sector geometry changed"},
		{name: "source on target", mutate: func(ops *fullFlashTargetOpenOps, _ *device.BlockDevice, _ FullFlashTargetPreflightPlan) {
			ops.ensureSourceOutside = func(*os.File, device.BlockDevice) error { return errors.New("source is on target") }
		}, want: "source is on target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, sourceLease, dev, ops := newSessionFixture(t)
			defer fixture.file.Close()
			defer sourceLease.Close()
			test.mutate(&ops, &dev, fixture.preflight)
			if test.name == "target identity" || test.name == "capacity" || test.name == "became mounted" {
				ops.revalidateTarget = func(string, uint64) (device.BlockDevice, uint64, error) {
					return dev, fixture.preflight.KernelDeviceID, nil
				}
			}
			session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, fixture.preflight, ops)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				if session != nil {
					session.Close()
				}
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestAcquireExclusiveFullFlashTargetRejectsClosedSourceAndCancelledContext(t *testing.T) {
	fixture := newFullFlashSourceLeaseFixture(t)
	defer fixture.file.Close()
	sourceLease, err := AcquireAuthenticatedFullFlashSourceLease(context.Background(), fixture.file, fixture.identity, fixture.chain.activation, catalogChainEvaluationTime, fixture.policy, fixture.request, fixture.preflight)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceLease.Close(); err != nil {
		t.Fatal(err)
	}
	ops := completeTargetSessionTestOps()
	if session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, fixture.preflight, ops); err == nil || !strings.Contains(err.Error(), "closed") {
		if session != nil {
			session.Close()
		}
		t.Fatalf("closed source error=%v", err)
	}
	var nilContext context.Context
	if session, err := acquireExclusiveFullFlashTargetWithOps(nilContext, sourceLease, fixture.preflight, ops); err == nil || !strings.Contains(err.Error(), "context is nil") {
		if session != nil {
			session.Close()
		}
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session, err := acquireExclusiveFullFlashTargetWithOps(ctx, sourceLease, fixture.preflight, ops); !errors.Is(err, context.Canceled) {
		if session != nil {
			session.Close()
		}
		t.Fatalf("cancelled context error=%v", err)
	}
}

func TestValidateFullFlashTargetSessionEvidenceRejectsTampering(t *testing.T) {
	evidence := FullFlashTargetSessionEvidence{
		Schema: fullFlashTargetSessionEvidenceSchema, Mode: "ffu-exclusive-target-session",
		SourceLeaseEvidenceSHA256: strings.Repeat("1", 64), FullFlashTargetPreflightSHA256: strings.Repeat("2", 64),
		FullFlashValidationPlanSHA256: strings.Repeat("3", 64), RestoreTargetPlanSHA256: strings.Repeat("4", 64),
		AuthenticatedIntegritySHA256: strings.Repeat("5", 64), DevicePath: "/dev/test-ffu",
		ExpectedTargetIdentity: strings.Repeat("6", 64), RediscoveredTargetIdentity: strings.Repeat("6", 64),
		TargetSizeBytes: 1 << 20, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 512, StoreBlockSizeBytes: 512,
		ExpectedKernelDeviceID: 7, ObservedKernelDeviceID: 7, MajorMinor: "7:1", MutationBytes: 4096,
		SourceLeaseHeld: true, TargetOpenedReadWrite: true, KernelExclusiveOpen: true, NoFollowOpen: true,
		MountedTargetsAbsent: true, TargetDescriptorVerified: true, TargetPolicyRevalidated: true,
		TargetGeometryRevalidated: true, SourceOutsideTargetConfirmed: true, TargetAccessAcquired: true,
		Warnings: fullFlashTargetSessionWarnings(), Limitations: fullFlashTargetSessionLimitations(),
	}
	evidence.PlanSHA256 = fullFlashTargetSessionEvidenceDigest(evidence)
	if err := validateFullFlashTargetSessionEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	evidence.MajorMinor = "7:2"
	if err := validateFullFlashTargetSessionEvidence(evidence); err == nil || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("tamper error=%v", err)
	}
}

func completeTargetSessionTestOps() fullFlashTargetOpenOps {
	return fullFlashTargetOpenOps{
		openTarget:       func(string) (*os.File, error) { return nil, errors.New("unexpected target open") },
		verifyOpenTarget: func(*os.File, uint64, uint64) error { return nil },
		revalidateTarget: func(string, uint64) (device.BlockDevice, uint64, error) {
			return device.BlockDevice{}, 0, nil
		},
		readSectorGeometry:  func(string) (uint64, uint64, error) { return 512, 512, nil },
		ensureSourceOutside: func(*os.File, device.BlockDevice) error { return nil },
	}
}

func exclusiveTargetSessionTestDevice(preflight FullFlashTargetPreflightPlan) device.BlockDevice {
	return device.BlockDevice{
		Name:       "test-ffu",
		Path:       preflight.DevicePath,
		Type:       "disk",
		Size:       preflight.TargetSizeBytes,
		Vendor:     "RufusArm64",
		Model:      "source lease fixture",
		Transport:  "usb",
		Hotplug:    true,
		MajorMinor: "7:1",
		Serial:     "source-lease-serial",
		WWN:        "source-lease-wwn",
	}
}
