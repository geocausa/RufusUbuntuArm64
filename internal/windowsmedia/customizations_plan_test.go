//go:build linux

package windowsmedia

import (
	"context"
	"errors"
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

func TestValidateCustomizationTargetSystemRejectsSkuSiPolicyAfterAutoResolvesToBIOS(t *testing.T) {
	options := windowsconfig.Options{ApplySkuSiPolicy: true}
	if err := validateCustomizationLayout(options, "bios", "fat32"); err == nil || !strings.Contains(err.Error(), "requires a resolved UEFI") {
		t.Fatalf("BIOS target error = %v", err)
	}
	if err := validateCustomizationLayout(options, "UEFI", "fat32"); err != nil {
		t.Fatalf("UEFI target rejected: %v", err)
	}
	if err := validateCustomizationLayout(windowsconfig.Options{}, "bios", "fat32"); err != nil {
		t.Fatalf("unselected policy affected BIOS media: %v", err)
	}
}

func TestValidateCustomizationLayoutBoundsSilentInstallToGuardedUEFI(t *testing.T) {
	options := windowsconfig.Options{SilentInstall: true}
	for _, filesystem := range []string{"ntfs", "fat32"} {
		if err := validateCustomizationLayout(options, "uefi", filesystem); err != nil {
			t.Fatalf("UEFI/%s rejected: %v", filesystem, err)
		}
	}
	for _, layout := range []struct{ target, filesystem string }{{"bios", "ntfs"}, {"bios", "fat32"}, {"uefi", "ext4"}} {
		if err := validateCustomizationLayout(options, layout.target, layout.filesystem); err == nil || !strings.Contains(err.Error(), "resolved UEFI") {
			t.Fatalf("layout %s/%s error=%v", layout.target, layout.filesystem, err)
		}
	}
}

func TestInspectPlanCustomizationMetadataScopesBootLanguageFailure(t *testing.T) {
	previousSetup := inspectPlanSetupMetadata
	previousBoot := inspectPlanBootMetadata
	t.Cleanup(func() {
		inspectPlanSetupMetadata = previousSetup
		inspectPlanBootMetadata = previousBoot
	})
	installMetadata := windowsconfig.MediaMetadata{
		ProductName: "Windows 11 Pro", Version: "10.0.26100", Architecture: "arm64", InstallationType: "Client",
		ImageCount: 1, Images: []windowsconfig.WindowsImage{{Index: 3, Name: "Windows 11 Pro"}},
	}
	inspectPlanSetupMetadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return installMetadata, nil
	}
	inspectPlanBootMetadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{}, errors.New("unreadable boot metadata")
	}
	plan := mediaPlan{InstallPath: "/media/sources/install.wim", BootWIMPath: "/media/sources/boot.wim"}
	metadata, err := inspectPlanCustomizationMetadata(context.Background(), plan, false)
	if err != nil || metadata.ProductName != installMetadata.ProductName || metadata.BootLanguage != "" {
		t.Fatalf("optional boot-language probe = %#v, %v", metadata, err)
	}
	if _, err := inspectPlanCustomizationMetadata(context.Background(), plan, true); err == nil || !strings.Contains(err.Error(), "boot language") {
		t.Fatalf("required boot-language error=%v", err)
	}
}

func TestInspectPlanCustomizationMetadataBindsSetupImageTwoAndExistingAnswer(t *testing.T) {
	previousSetup := inspectPlanSetupMetadata
	previousBoot := inspectPlanBootMetadata
	t.Cleanup(func() {
		inspectPlanSetupMetadata = previousSetup
		inspectPlanBootMetadata = previousBoot
	})
	inspectPlanSetupMetadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{
			ProductName: "Windows 11 Pro", Version: "10.0.26100", Architecture: "arm64", InstallationType: "Client",
			ImageCount: 1, Images: []windowsconfig.WindowsImage{{Index: 3, Name: "Windows 11 Pro"}},
		}, nil
	}
	inspectPlanBootMetadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{Images: []windowsconfig.WindowsImage{
			{Index: 1, Name: "Windows PE", DefaultLanguage: "fr-FR"},
			{Index: 2, Name: "Windows Setup", DefaultLanguage: "en-GB"},
		}}, nil
	}
	plan := mediaPlan{
		InstallPath: "/media/sources/install.wim", BootWIMPath: "/media/sources/boot.wim",
		ExistingPantherAnswerPath: "/media/sources/$OEM$/$$/Panther/unattend.xml",
	}
	metadata, err := inspectPlanCustomizationMetadata(context.Background(), plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BootLanguage != "en-GB" || metadata.ExistingUnattendPath != "sources/$OEM$/$$/Panther/unattend.xml" {
		t.Fatalf("metadata=%#v", metadata)
	}
}
