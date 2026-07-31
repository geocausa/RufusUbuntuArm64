//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

// CustomizationPreparation is the authoritative result shared by the writer,
// CLI inspection, and graphical interface.
type CustomizationPreparation struct {
	Metadata     windowsconfig.MediaMetadata     `json:"metadata"`
	Capabilities windowsconfig.CapabilityProfile `json:"capabilities"`
	AnswerFile   []byte                          `json:"-"`
}

var inspectCustomizationWIMMetadata = InspectWIMSetupMetadata

// PrepareCustomizations reads bounded metadata from a Windows installation
// image, validates every selected setup option against that media, and only
// then generates autounattend.xml. No selected options remains a no-op, but the
// metadata and capability profile are still returned for inspection clients.
func PrepareCustomizations(ctx context.Context, imagePath, answerArchitecture string, options windowsconfig.Options) (CustomizationPreparation, error) {
	metadata, err := inspectCustomizationWIMMetadata(ctx, imagePath)
	if err != nil {
		return CustomizationPreparation{}, fmt.Errorf("inspect Windows setup capabilities: %w", err)
	}
	return PrepareCustomizationsForMetadata(metadata, answerArchitecture, options)
}

// PrepareCustomizationsForMetadata applies the exact same fail-closed policy
// to already-inspected metadata. Keeping this policy-only half separate makes
// it straightforward for inspection clients and tests to consume one contract.
func PrepareCustomizationsForMetadata(metadata windowsconfig.MediaMetadata, answerArchitecture string, options windowsconfig.Options) (CustomizationPreparation, error) {
	profile := windowsconfig.Capabilities(metadata)
	result := CustomizationPreparation{Metadata: metadata, Capabilities: profile}
	if err := windowsconfig.ValidateForMedia(metadata, options); err != nil {
		return result, err
	}
	resolvedOptions := options
	if options.SilentInstall {
		matched := false
		for _, image := range metadata.Images {
			if image.Index == options.InstallImageIndex {
				matched = true
				break
			}
		}
		if !matched {
			return result, fmt.Errorf("silent installation image index %d is not present in the inspected Windows payload", options.InstallImageIndex)
		}
		resolvedOptions.BootLanguage = metadata.BootLanguage
	}
	answer, err := windowsconfig.Generate(answerArchitecture, resolvedOptions)
	if err != nil {
		return result, fmt.Errorf("generate Windows answer file: %w", err)
	}
	result.AnswerFile = answer
	return result, nil
}

func validateCustomizationLayout(options windowsconfig.Options, targetSystem, filesystem string) error {
	target := strings.ToLower(strings.TrimSpace(targetSystem))
	format := strings.ToLower(strings.TrimSpace(filesystem))
	if options.ApplySkuSiPolicy && target != "uefi" {
		return fmt.Errorf("SkuSiPolicy deployment requires a resolved UEFI Windows target; BIOS/CSM media has no EFI System Partition")
	}
	if options.SilentInstall && (target != "uefi" || (format != "fat32" && format != "ntfs")) {
		return fmt.Errorf("silent installation requires resolved UEFI FAT32 or NTFS media with a verified partition-2 guard for disk numbering")
	}
	return nil
}

// customizationPreparer keeps the writer integration testable without invoking
// an external WIM engine. Production callers pass PrepareCustomizations.
type customizationPreparer func(context.Context, string, string, windowsconfig.Options) (CustomizationPreparation, error)

var inspectPlanSetupMetadata = InspectWIMSetupMetadata
var inspectPlanBootMetadata = InspectWIMMetadata

// preparePlanAnswerFile preserves the historical zero-option no-op. Metadata is
// required only when at least one customization is selected; this keeps ordinary
// Windows media creation compatible with images whose product metadata cannot be
// classified while failing closed before any customized answer file is produced.
func preparePlanAnswerFile(ctx context.Context, plan mediaPlan, options windowsconfig.Options, prepare customizationPreparer) ([]byte, error) {
	if !options.Enabled() {
		return windowsconfig.Generate(plan.Architecture, options)
	}
	if options.SilentInstall {
		metadata, err := inspectPlanCustomizationMetadata(ctx, plan, true)
		if err != nil {
			return nil, err
		}
		result, err := PrepareCustomizationsForMetadata(metadata, plan.Architecture, options)
		if err != nil {
			return nil, err
		}
		return result.AnswerFile, nil
	}
	imagePath, err := customizationImagePath(plan)
	if err != nil {
		return nil, err
	}
	result, err := prepare(ctx, imagePath, plan.Architecture, options)
	if err != nil {
		return nil, err
	}
	return result.AnswerFile, nil
}

func inspectPlanCustomizationMetadata(ctx context.Context, plan mediaPlan, requireBootLanguage bool) (windowsconfig.MediaMetadata, error) {
	imagePath, err := customizationImagePath(plan)
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	metadata, err := inspectPlanSetupMetadata(ctx, imagePath)
	if err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect Windows setup capabilities: %w", err)
	}
	bootMetadata, bootErr := inspectPlanBootMetadata(ctx, plan.BootWIMPath)
	if bootErr != nil {
		if requireBootLanguage {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect Windows Setup boot language: %w", bootErr)
		}
	} else if setupImage, ok := wimImageByIndex(bootMetadata, 2); ok {
		metadata.BootLanguage = strings.TrimSpace(setupImage.DefaultLanguage)
	}
	if requireBootLanguage && metadata.BootLanguage == "" {
		return windowsconfig.MediaMetadata{}, errors.New("boot.wim image 2 does not publish a default Windows Setup language")
	}
	if plan.ExistingAnswerPath != "" {
		metadata.ExistingUnattendPath = "autounattend.xml"
	} else if plan.ExistingPantherAnswerPath != "" {
		metadata.ExistingUnattendPath = "sources/$OEM$/$$/Panther/unattend.xml"
	}
	return metadata, nil
}

func customizationImagePath(plan mediaPlan) (string, error) {
	if plan.InstallPath != "" {
		return plan.InstallPath, nil
	}
	if len(plan.ExistingSplitFiles) > 0 {
		return plan.ExistingSplitFiles[0], nil
	}
	return "", fmt.Errorf("windows installation payload path is unavailable for setup capability inspection")
}
