//go:build linux

package windowsmedia

import (
	"context"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func qualifiedArchitectureMetadata() windowsconfig.MediaMetadata {
	return windowsconfig.MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "arm64",
		InstallationType: "Client",
	}
}

func TestValidateWindowsCA2023ArchitectureRequiresThreeWayAgreement(t *testing.T) {
	metadata := windowsconfig.MediaMetadata{Architecture: "arm64"}
	plan := &WindowsCA2023Plan{Architecture: "arm64"}
	if err := validateWindowsCA2023Architecture(metadata, plan); err != nil {
		t.Fatalf("matching install and staged boot architectures rejected: %v", err)
	}

	plan.Architecture = "amd64"
	if err := validateWindowsCA2023Architecture(metadata, plan); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected cross-image architecture mismatch refusal, got %v", err)
	}
}

func TestValidateWindowsCA2023ArchitectureRejectsMissingEvidence(t *testing.T) {
	if err := validateWindowsCA2023Architecture(windowsconfig.MediaMetadata{Architecture: "arm64"}, nil); err == nil {
		t.Fatal("missing replacement plan unexpectedly accepted")
	}
	if err := validateWindowsCA2023Architecture(windowsconfig.MediaMetadata{}, &WindowsCA2023Plan{Architecture: "arm64"}); err == nil {
		t.Fatal("missing install architecture unexpectedly accepted")
	}
	capability := WindowsCA2023Capability{Available: true, ImageIndex: 2}
	if err := validateWindowsCA2023Selection(qualifiedArchitectureMetadata(), capability, "uefi", "fat32"); err == nil || !strings.Contains(err.Error(), "architecture evidence") {
		t.Fatalf("missing boot.wim architecture evidence unexpectedly accepted: %v", err)
	}
}

func TestValidateWindowsCA2023SelectionBindsInstallAndBootWIMArchitecture(t *testing.T) {
	capability := WindowsCA2023Capability{Available: true, ImageIndex: 2, Architecture: "arm64"}
	if err := validateWindowsCA2023Selection(qualifiedArchitectureMetadata(), capability, "uefi", "fat32"); err != nil {
		t.Fatalf("matching install and boot.wim architecture rejected: %v", err)
	}

	capability.Architecture = "amd64"
	if err := validateWindowsCA2023Selection(qualifiedArchitectureMetadata(), capability, "uefi", "fat32"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected install/boot.wim architecture mismatch refusal, got %v", err)
	}
}

func TestInspectWindowsCA2023CapabilityRejectsUnsupportedBootArchitectureBeforePathProbing(t *testing.T) {
	originalMetadata := inspectWindowsCA2023Metadata
	originalExecutable := windowsCA2023WIMExecutable
	originalPath := inspectWindowsCA2023WIMPath
	inspectWindowsCA2023Metadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{ImageCount: 2, Architecture: "riscv64"}, nil
	}
	windowsCA2023WIMExecutable = func() (string, error) {
		t.Fatal("unsupported boot.wim architecture reached WIM executable lookup")
		return "", nil
	}
	inspectWindowsCA2023WIMPath = func(context.Context, string, string, int, string) (bool, error) {
		t.Fatal("unsupported boot.wim architecture reached replacement-path probing")
		return false, nil
	}
	t.Cleanup(func() {
		inspectWindowsCA2023Metadata = originalMetadata
		windowsCA2023WIMExecutable = originalExecutable
		inspectWindowsCA2023WIMPath = originalPath
	})

	capability, err := InspectWindowsCA2023Capability(context.Background(), "boot.wim")
	if err != nil {
		t.Fatal(err)
	}
	if capability.Available || !strings.Contains(capability.Reason, "unsupported") {
		t.Fatalf("unsupported boot.wim architecture was not refused: %+v", capability)
	}
}
