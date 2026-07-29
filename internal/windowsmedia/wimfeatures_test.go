//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestInspectWIMPathInEveryImageRequiresEveryEdition(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	script := `#!/bin/sh
if [ "$1" = dir ] && [ "$3" = 1 ]; then
  printf '%s\n' '/Windows/System32/SecureBootUpdates/SkuSiPolicy.p7b'
  exit 0
fi
if [ "$1" = dir ] && [ "$3" = 2 ]; then
  echo 'The path does not exist in the WIM image' >&2
  exit 1
fi
exit 2
`
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	available, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err != nil || !available {
		t.Fatalf("image 1 capability = %v, %v", available, err)
	}
	available, err = inspectWIMPath(context.Background(), tool, "install.wim", 2, skuSiPolicyWIMPath)
	if err != nil || available {
		t.Fatalf("image 2 capability = %v, %v", available, err)
	}
}

func TestInspectWIMPathReportsOperationalFailure(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho 'corrupt WIM' >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err == nil || !strings.Contains(err.Error(), "corrupt wim") {
		t.Fatalf("operational error = %v", err)
	}
}

func TestSkuSiPolicyProbeFailureDisablesOnlyThatOption(t *testing.T) {
	original := inspectSkuSiPolicyInEveryImage
	inspectSkuSiPolicyInEveryImage = func(context.Context, string, int, string) (bool, error) {
		return false, errors.New("policy probe unavailable")
	}
	t.Cleanup(func() { inspectSkuSiPolicyInEveryImage = original })

	metadata := enrichSkuSiPolicyMetadata(context.Background(), "install.wim", windowsconfig.MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "arm64",
		InstallationType: "Client",
		ImageCount:       1,
	})
	profile := windowsconfig.Capabilities(metadata)
	if profile.ApplySkuSiPolicy.Enabled || !strings.Contains(profile.ApplySkuSiPolicy.Reason, "policy probe unavailable") {
		t.Fatalf("policy capability = %#v", profile.ApplySkuSiPolicy)
	}
	if !profile.LocalAccount.Enabled || !profile.DisableBitLocker.Enabled || !profile.BypassHardwareChecks.Enabled {
		t.Fatalf("unrelated capabilities were suppressed: %#v", profile)
	}
}
