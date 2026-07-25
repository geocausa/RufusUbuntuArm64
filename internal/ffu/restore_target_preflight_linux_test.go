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

func TestBuildFullFlashTargetPreflight(t *testing.T) {
	validation, dev := fullFlashPreflightTestFixture(t)
	dev.Children = []device.BlockDevice{
		{Path: "/dev/test-ffu1", Type: "part", Mountpoints: []string{"/media/user/FFU"}},
		{Path: "/dev/test-ffu2", Type: "part", Mountpoints: []string{"/mnt/restore"}},
	}
	plan, err := buildFullFlashTargetPreflight(validation, dev, 0x701, 512, 512, true)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.TargetDiscoveryCompleted || !plan.WholeDiskConfirmed || !plan.NormalRemovableTargetConfirmed || !plan.RunningSystemDiskExcluded || !plan.ProtectedMountsExcluded {
		t.Fatalf("target policy did not complete: %#v", plan)
	}
	if !plan.TargetIdentityRevalidated || !plan.TargetCapacityRevalidated || !plan.TargetGeometryRevalidated || plan.FixedDiskOverrideAllowed || !plan.PrivilegedOpenRequired || plan.ExecutionSupported {
		t.Fatalf("preflight crossed or missed a boundary: %#v", plan)
	}
	if plan.ExpectedTargetIdentity != validation.ExpectedTargetIdentity || plan.RediscoveredTargetIdentity != validation.ExpectedTargetIdentity || plan.TargetSizeBytes != validation.TargetSizeBytes || plan.MutationBytes != validation.MutationBytes {
		t.Fatalf("preflight lost source or target binding: %#v", plan)
	}
	if !plan.UnmountRequired || len(plan.MountedTargets) != 2 || plan.MountedTargets[0].DevicePath != "/dev/test-ffu1" || plan.MountedTargets[1].Mountpoint != "/mnt/restore" {
		t.Fatalf("unexpected mount evidence: %#v", plan.MountedTargets)
	}
	if plan.PlanSHA256 != fullFlashTargetPreflightDigest(plan) {
		t.Fatal("preflight plan digest mismatch")
	}
	second, err := buildFullFlashTargetPreflight(validation, dev, 0x701, 512, 512, true)
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != plan.PlanSHA256 {
		t.Fatal("identical preflight facts produced different evidence")
	}
}

func TestBuildFullFlashTargetPreflightRejectsUnsafeSnapshots(t *testing.T) {
	validation, validDevice := fullFlashPreflightTestFixture(t)
	tests := []struct {
		name     string
		mutate   func(*device.BlockDevice)
		kernelID uint64
		logical  uint64
		physical uint64
		rootSafe bool
		want     string
	}{
		{name: "partition", mutate: func(dev *device.BlockDevice) { dev.Type = "part" }, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "whole disk"},
		{name: "read only", mutate: func(dev *device.BlockDevice) { dev.ReadOnly = true }, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "read-only"},
		{name: "fixed disk", mutate: func(dev *device.BlockDevice) { dev.Transport = ""; dev.Removable = false }, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "not marked removable or USB"},
		{name: "identity changed", mutate: func(dev *device.BlockDevice) { dev.MajorMinor = "8:9" }, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "identity differs"},
		{name: "capacity changed", mutate: func(dev *device.BlockDevice) { dev.Size += 4096 }, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "capacity changed"},
		{name: "geometry changed", mutate: func(dev *device.BlockDevice) {}, kernelID: 1, logical: 4096, physical: 4096, rootSafe: true, want: "sector geometry changed"},
		{name: "zero kernel identity", mutate: func(dev *device.BlockDevice) {}, kernelID: 0, logical: 512, physical: 512, rootSafe: true, want: "kernel device identity is zero"},
		{name: "system disk unresolved", mutate: func(dev *device.BlockDevice) {}, kernelID: 1, logical: 512, physical: 512, rootSafe: false, want: "not excluded the running system disk"},
		{name: "protected mount", mutate: func(dev *device.BlockDevice) {
			dev.Children = []device.BlockDevice{{Path: "/dev/test-ffu1", Type: "part", Mountpoints: []string{"/home"}}}
		}, kernelID: 1, logical: 512, physical: 512, rootSafe: true, want: "running system"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := validDevice
			test.mutate(&dev)
			_, err := buildFullFlashTargetPreflight(validation, dev, test.kernelID, test.logical, test.physical, test.rootSafe)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestReadFFUTargetSectorGeometryAt(t *testing.T) {
	root := t.TempDir()
	queue := filepath.Join(root, "test-ffu", "queue")
	if err := os.MkdirAll(queue, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, "logical_block_size"), []byte("512\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, "physical_block_size"), []byte("4096\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logical, physical, err := readFFUTargetSectorGeometryAt(root, "test-ffu")
	if err != nil {
		t.Fatal(err)
	}
	if logical != 512 || physical != 4096 {
		t.Fatalf("geometry=%d/%d", logical, physical)
	}
	if _, _, err := readFFUTargetSectorGeometryAt(root, "../escape"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unsafe name error=%v", err)
	}
	if err := os.WriteFile(filepath.Join(queue, "logical_block_size"), []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFFUTargetSectorGeometryAt(root, "test-ffu"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("malformed geometry error=%v", err)
	}
}

func TestValidateFullFlashTargetPreflightRejectsTampering(t *testing.T) {
	validation, dev := fullFlashPreflightTestFixture(t)
	plan, err := buildFullFlashTargetPreflight(validation, dev, 0x701, 512, 512, true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Model = "different"
	if err := validateFullFlashTargetPreflightPlan(plan); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestDiscoverFullFlashTargetPreflightRejectsNilAndCancelledContext(t *testing.T) {
	var nilContext context.Context
	if _, err := DiscoverFullFlashTargetPreflight(nilContext, FullFlashValidationPlan{}); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiscoverFullFlashTargetPreflight(ctx, FullFlashValidationPlan{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
}

func fullFlashPreflightTestFixture(t testing.TB) (FullFlashValidationPlan, device.BlockDevice) {
	t.Helper()
	fixture := newFullFlashGateFixture(t, fullFlashUpdateType, false)
	policy := catalogPublisherTestPolicy(fixture, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(fixture.data), uint64(len(fixture.data)))
	if err != nil {
		t.Fatal(err)
	}
	dev := device.BlockDevice{
		Name:       "test-ffu",
		Path:       "/dev/test-ffu",
		Type:       "disk",
		Size:       descriptor.MinimumTargetBytes,
		Vendor:     "RufusArm64",
		Model:      "FFU preflight fixture",
		Transport:  "usb",
		Removable:  false,
		Hotplug:    true,
		MajorMinor: "7:1",
		Serial:     "preflight-serial",
		WWN:        "preflight-wwn",
	}
	identity := device.IdentityToken(dev)
	request := RestoreTargetRequest{
		DevicePath:              dev.Path,
		ExpectedTargetIdentity:  identity,
		TargetSizeBytes:         dev.Size,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}
	_, validation, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	return validation, dev
}
