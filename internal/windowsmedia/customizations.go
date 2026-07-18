//go:build linux

package windowsmedia

import (
	"context"
	"fmt"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

// CustomizationPreparation is the authoritative result shared by the writer,
// CLI inspection, and graphical interface.
type CustomizationPreparation struct {
	Metadata     windowsconfig.MediaMetadata     `json:"metadata"`
	Capabilities windowsconfig.CapabilityProfile `json:"capabilities"`
	AnswerFile   []byte                          `json:"-"`
}

// PrepareCustomizations reads bounded metadata from a Windows installation
// image, validates every selected setup option against that media, and only
// then generates autounattend.xml. No selected options remains a no-op, but the
// metadata and capability profile are still returned for inspection clients.
func PrepareCustomizations(ctx context.Context, imagePath, answerArchitecture string, options windowsconfig.Options) (CustomizationPreparation, error) {
	metadata, err := InspectWIMMetadata(ctx, imagePath)
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
	answer, err := windowsconfig.Generate(answerArchitecture, options)
	if err != nil {
		return result, fmt.Errorf("generate Windows answer file: %w", err)
	}
	result.AnswerFile = answer
	return result, nil
}
