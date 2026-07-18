//go:build linux

package windowsmedia

import (
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestPrepareCustomizationsForMetadata(t *testing.T) {
	windows11 := windowsconfig.MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "arm64",
		InstallationType: "Client",
	}
	prepared, err := PrepareCustomizationsForMetadata(windows11, "arm64", windowsconfig.Options{
		BypassHardwareChecks: true,
		BypassOnlineAccount:  true,
	})
	if err != nil {
		t.Fatalf("prepare Windows 11 customizations: %v", err)
	}
	if !prepared.Capabilities.Recognized || !prepared.Capabilities.BypassHardwareChecks.Enabled {
		t.Fatalf("unexpected Windows 11 capabilities: %#v", prepared.Capabilities)
	}
	if len(prepared.AnswerFile) == 0 || !strings.Contains(string(prepared.AnswerFile), "BypassTPMCheck") {
		t.Fatalf("generated answer file does not contain the requested hardware bypass")
	}

	windows10 := windowsconfig.MediaMetadata{
		ProductName:      "Windows 10 Pro",
		Version:          "10.0.19045",
		Architecture:     "amd64",
		InstallationType: "Client",
	}
	prepared, err = PrepareCustomizationsForMetadata(windows10, "amd64", windowsconfig.Options{BypassHardwareChecks: true})
	if err == nil || !strings.Contains(err.Error(), "Windows 11") {
		t.Fatalf("Windows 10 hardware bypass error = %v", err)
	}
	if prepared.Capabilities.BypassHardwareChecks.Enabled {
		t.Fatalf("Windows 10 hardware bypass unexpectedly enabled: %#v", prepared.Capabilities)
	}
}

func TestPrepareCustomizationsForMetadataLeavesZeroOptionsAsNoOp(t *testing.T) {
	unknown := windowsconfig.MediaMetadata{Architecture: "arm64"}
	prepared, err := PrepareCustomizationsForMetadata(unknown, "arm64", windowsconfig.Options{})
	if err != nil {
		t.Fatalf("zero options must remain a no-op: %v", err)
	}
	if prepared.Capabilities.Recognized {
		t.Fatalf("unknown metadata unexpectedly recognized: %#v", prepared.Capabilities)
	}
	if len(prepared.AnswerFile) != 0 {
		t.Fatalf("zero options generated an answer file")
	}
}
