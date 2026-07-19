//go:build linux

package windowsmedia

import (
	"context"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestPreparePlanAnswerFileZeroOptionsDoesNotInspectMetadata(t *testing.T) {
	called := false
	answer, err := preparePlanAnswerFile(context.Background(), mediaPlan{Architecture: "ARM64 UEFI"}, windowsconfig.Options{}, func(context.Context, string, string, windowsconfig.Options) (CustomizationPreparation, error) {
		called = true
		return CustomizationPreparation{}, nil
	})
	if err != nil {
		t.Fatalf("prepare zero-option answer file: %v", err)
	}
	if called {
		t.Fatal("metadata preparer was called for zero selected options")
	}
	if len(answer) != 0 {
		t.Fatalf("zero selected options produced %d answer-file bytes", len(answer))
	}
}

func TestPreparePlanAnswerFileUsesExistingSplitPayload(t *testing.T) {
	const firstPart = "/media/sources/install.swm"
	plan := mediaPlan{Architecture: "ARM64 UEFI", ExistingSplitFiles: []string{firstPart, "/media/sources/install2.swm"}}
	want := []byte("answer")
	answer, err := preparePlanAnswerFile(context.Background(), plan, windowsconfig.Options{BypassHardwareChecks: true}, func(_ context.Context, imagePath, architecture string, options windowsconfig.Options) (CustomizationPreparation, error) {
		if imagePath != firstPart {
			t.Fatalf("metadata path = %q, want %q", imagePath, firstPart)
		}
		if architecture != plan.Architecture {
			t.Fatalf("architecture = %q, want %q", architecture, plan.Architecture)
		}
		if !options.BypassHardwareChecks {
			t.Fatal("selected options were not forwarded")
		}
		return CustomizationPreparation{AnswerFile: want}, nil
	})
	if err != nil {
		t.Fatalf("prepare split-media answer file: %v", err)
	}
	if string(answer) != string(want) {
		t.Fatalf("answer = %q, want %q", answer, want)
	}
}

func TestPreparePlanAnswerFileRejectsMissingPayloadForSelectedOptions(t *testing.T) {
	_, err := preparePlanAnswerFile(context.Background(), mediaPlan{Architecture: "ARM64 UEFI"}, windowsconfig.Options{LocalAccount: "tester"}, PrepareCustomizations)
	if err == nil || !strings.Contains(err.Error(), "payload path is unavailable") {
		t.Fatalf("error = %v, want missing payload path", err)
	}
}
