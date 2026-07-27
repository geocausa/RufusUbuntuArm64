//go:build linux

package ffu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestPrivilegedSinglePhaseFullFlashLoopExecution(t *testing.T) {
	loopPath := os.Getenv("RUFUSARM64_FFU_LOOP_DEVICE")
	sizeText := os.Getenv("RUFUSARM64_FFU_LOOP_SIZE")
	if loopPath == "" || sizeText == "" {
		t.Skip("privileged FFU loop-device qualification is not enabled")
	}
	targetSize, err := strconv.ParseUint(sizeText, 10, 64)
	if err != nil || targetSize == 0 {
		t.Fatalf("invalid loop target size %q", sizeText)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(loopPath, &stat); err != nil {
		t.Fatal(err)
	}
	kernelID := uint64(stat.Rdev)
	if kernelID == 0 {
		t.Fatal("loop target has a zero kernel device identity")
	}

	chain := newSinglePhaseFullFlashGateFixture(t)
	policy := catalogPublisherTestPolicy(chain, catalogPublisherIdentityCertificate)
	_, descriptor, err := PlanSingleStoreV1(bytes.NewReader(chain.data), uint64(len(chain.data)))
	if err != nil {
		t.Fatal(err)
	}
	if targetSize < descriptor.MinimumTargetBytes || targetSize%descriptor.BlockSizeBytes != 0 {
		t.Fatalf("loop target size %d is incompatible with FFU minimum %d and block size %d", targetSize, descriptor.MinimumTargetBytes, descriptor.BlockSizeBytes)
	}

	dev := device.BlockDevice{
		Name:       filepath.Base(loopPath),
		Path:       loopPath,
		Type:       "disk",
		Size:       targetSize,
		Vendor:     "RufusArm64",
		Model:      "privileged FFU loop qualification",
		Transport:  "usb",
		Hotplug:    true,
		MajorMinor: fmt.Sprintf("loop-rdev-%d", kernelID),
		Serial:     "ffu-loop-qualification",
		WWN:        "ffu-loop-qualification",
	}
	request := RestoreTargetRequest{
		DevicePath:              dev.Path,
		ExpectedTargetIdentity:  device.IdentityToken(dev),
		TargetSizeBytes:         targetSize,
		LogicalSectorSizeBytes:  512,
		PhysicalSectorSizeBytes: 512,
	}
	targetPlan, fullPlan, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		context.Background(), bytes.NewReader(chain.data), uint64(len(chain.data)), chain.activation, catalogChainEvaluationTime, policy, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := buildFullFlashTargetPreflight(fullPlan, dev, kernelID, 512, 512, true)
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
	defer sourceFile.Close()
	source, err := AcquireAuthenticatedFullFlashSourceLease(
		context.Background(), sourceFile, identity, chain.activation, catalogChainEvaluationTime, policy, request, preflight,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	original := bytes.Repeat([]byte{0x5a}, int(targetSize))
	seedTarget, err := os.OpenFile(loopPath, os.O_WRONLY|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLoopQualificationFull(seedTarget, original); err != nil {
		seedTarget.Close()
		t.Fatal(err)
	}
	if err := seedTarget.Sync(); err != nil {
		seedTarget.Close()
		t.Fatal(err)
	}
	if err := seedTarget.Close(); err != nil {
		t.Fatal(err)
	}

	ops := fullFlashTargetOpenOps{
		openTarget: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR|syscall.O_EXCL|syscall.O_NOFOLLOW, 0)
		},
		verifyOpenTarget: safety.VerifyOpenDevice,
		revalidateTarget: func(path string, expectedKernelID uint64) (device.BlockDevice, uint64, error) {
			if path != loopPath || expectedKernelID != kernelID {
				return device.BlockDevice{}, 0, errors.New("loop target binding changed")
			}
			return dev, kernelID, nil
		},
		readSectorGeometry: func(deviceName string) (uint64, uint64, error) {
			if deviceName != dev.Name {
				return 0, 0, errors.New("loop device name changed")
			}
			return 512, 512, nil
		},
		ensureSourceOutside: func(file *os.File, target device.BlockDevice) error {
			if file != sourceFile || target.Path != loopPath {
				return errors.New("loop source-target separation inputs changed")
			}
			return nil
		},
	}
	target, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), source, preflight, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetEvidence, err := target.Evidence()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := ConfirmExclusiveFullFlashTarget(
		context.Background(), target, expectedFullFlashConfirmationPhrase(targetEvidence.DevicePath, targetEvidence.TargetSizeBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), confirmation, descriptor, targetPlan, fullPlan)
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), original...)
	for _, operation := range authorization.writeOrder.Operations {
		payload := make([]byte, operation.PayloadLength)
		if err := readLoopQualificationAt(sourceFile, payload, int64(operation.PayloadOffset)); err != nil {
			t.Fatal(err)
		}
		copy(expected[operation.TargetOffset:operation.TargetOffset+operation.TargetLength], payload)
	}

	result, err := ExecuteAuthorizedSinglePhaseFullFlash(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ExecutionSucceeded || !result.SyncCompleted || !result.ReadbackCompleted || result.TargetMayBePartiallyModified || result.MutationBytesWritten != result.MutationBytesPlanned {
		t.Fatalf("loop execution result is incomplete: %#v", result)
	}
	actual := make([]byte, targetSize)
	if err := readLoopQualificationAt(target.file, actual, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("loop-device target differs from exact expected declaration-order image")
	}
	if err := authorization.Check(); err == nil {
		t.Fatal("loop execution did not consume the one-shot authorization")
	}
}

func writeLoopQualificationFull(file *os.File, data []byte) error {
	offset := int64(0)
	for len(data) > 0 {
		n, err := file.WriteAt(data, offset)
		if n > 0 {
			data = data[n:]
			offset += int64(n)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func readLoopQualificationAt(file *os.File, data []byte, offset int64) error {
	for len(data) > 0 {
		n, err := file.ReadAt(data, offset)
		if n > 0 {
			data = data[n:]
			offset += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) == 0 {
				return nil
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
