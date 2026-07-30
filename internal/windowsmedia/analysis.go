//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

// CapabilityAnalysis is the read-only Windows media identity returned to CLI
// and graphical clients before setup options are offered.
type CapabilityAnalysis struct {
	Metadata               windowsconfig.MediaMetadata     `json:"metadata"`
	Capabilities           windowsconfig.CapabilityProfile `json:"capabilities"`
	BootArchitecture       string                          `json:"boot_architecture,omitempty"`
	UEFICapable            bool                            `json:"uefi_capable"`
	BIOSCapable            bool                            `json:"bios_capable"`
	DefaultPartitionScheme string                          `json:"default_partition_scheme"`
	DefaultTargetSystem    string                          `json:"default_target_system"`
	DefaultFilesystem      string                          `json:"default_filesystem"`
	WindowsCA2023          WindowsCA2023Capability         `json:"windows_ca_2023"`
	PayloadKind            string                          `json:"payload_kind"`
	PayloadParts           int                             `json:"payload_parts"`
}

// AnalyzeCapabilities mounts an identity-bound Windows ISO read-only, inspects
// its installation payload and boot capabilities, and returns the shared
// setup-option profile. It never opens or modifies a target device.
func AnalyzeCapabilities(ctx context.Context, isoPath string, expectedSource sourcefile.Identity) (result CapabilityAnalysis, returnErr error) {
	isoFile, err := sourcefile.OpenRegular(isoPath, expectedSource)
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	defer isoFile.Close()
	stableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

	workDir, err := createWorkDir()
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	mountPath := filepath.Join(workDir, "iso")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		_ = os.RemoveAll(workDir)
		return CapabilityAnalysis{}, fmt.Errorf("create Windows analysis mount directory: %w", err)
	}
	mounted := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if mounted {
			if err := runQuiet(cleanupCtx, "umount", "--", mountPath); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("cleanup Windows analysis mount: %w", err))
			} else {
				mounted = false
			}
		}
		if !mounted {
			if err := os.RemoveAll(workDir); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove Windows analysis work directory: %w", err))
			}
		}
	}()

	if err := run(ctx, nil, "mount", "-o", "loop,ro,nosuid,nodev,noexec", "--", stableISOPath, mountPath); err != nil {
		return CapabilityAnalysis{}, fmt.Errorf("mount Windows ISO for read-only analysis: %w", err)
	}
	mounted = true
	plan, err := inspectMountedISO(mountPath)
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	if err := bindBootCapabilities(ctx, &plan); err != nil {
		return CapabilityAnalysis{}, err
	}
	defaultScheme, defaultTarget, err := resolveWindowsLayout(plan, "auto", "auto")
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	defaultFilesystem, err := resolveFilesystem("auto", validateFATCompatibility(mountPath, plan))
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	payloadKind, payloadParts, err := capabilityPayloadFacts(plan)
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	metadata, err := inspectPlanCustomizationMetadata(ctx, plan, false)
	if err != nil {
		return CapabilityAnalysis{}, err
	}
	ca2023, caErr := InspectWindowsCA2023Capability(ctx, plan.BootWIMPath)
	if caErr != nil {
		ca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader inspection failed: %v", caErr)}
	} else if ca2023.Available {
		staged, stageErr := StageWindowsCA2023(ctx, plan.BootWIMPath, mountPath, workDir, ca2023)
		if stageErr != nil {
			ca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader validation failed: %v", stageErr)}
		} else if architectureErr := validateWindowsCA2023Architecture(metadata, staged); architectureErr != nil {
			ca2023 = WindowsCA2023Capability{Reason: architectureErr.Error()}
		} else {
			ca2023 = summarizeWindowsCA2023Capability(ca2023, staged)
		}
	}
	metadata.WindowsCA2023Available = ca2023.Available
	metadata.WindowsCA2023UnavailableWhy = ca2023.Reason
	metadata.WindowsCA2023ImageIndex = ca2023.ImageIndex
	return CapabilityAnalysis{
		Metadata:               metadata,
		Capabilities:           windowsconfig.Capabilities(metadata),
		BootArchitecture:       plan.Architecture,
		UEFICapable:            plan.HasARM64 || plan.HasX64 || plan.HasX86,
		BIOSCapable:            plan.HasBIOS,
		DefaultPartitionScheme: defaultScheme,
		DefaultTargetSystem:    defaultTarget,
		DefaultFilesystem:      defaultFilesystem,
		WindowsCA2023:          ca2023,
		PayloadKind:            payloadKind,
		PayloadParts:           payloadParts,
	}, nil
}

func capabilityPayloadFacts(plan mediaPlan) (string, int, error) {
	hasSplit := len(plan.ExistingSplitFiles) > 0
	hasStandalone := strings.TrimSpace(plan.InstallPath) != ""
	if hasSplit && hasStandalone {
		return "", 0, errors.New("windows media plan contains conflicting standalone and split installation payloads")
	}
	if hasSplit {
		if len(plan.ExistingSplitFiles) > maxWindowsSplitParts {
			return "", 0, fmt.Errorf("windows media plan contains %d split parts; the supported limit is %d", len(plan.ExistingSplitFiles), maxWindowsSplitParts)
		}
		return "SWM", len(plan.ExistingSplitFiles), nil
	}
	switch strings.ToLower(filepath.Ext(plan.InstallPath)) {
	case ".wim":
		return "WIM", 1, nil
	case ".esd":
		return "ESD", 1, nil
	default:
		return "", 0, errors.New("windows installation payload type is unavailable for capability reporting")
	}
}
