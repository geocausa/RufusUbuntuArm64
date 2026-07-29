package windowsconfig

import (
	"strings"
	"testing"
)

func TestGenerateSkuSiPolicyUsesInstalledSystemAndAlwaysUnmountsESP(t *testing.T) {
	answer, err := Generate("arm64", Options{ApplySkuSiPolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	text := string(answer)
	for _, required := range []string{
		`%WINDIR%\System32\SecureBootUpdates\SkuSiPolicy.p7b`,
		`S:\EFI\Microsoft\Boot\SkuSiPolicy.p7b`,
		`mountvol S: /S`,
		`mountvol S: /D`,
		`set rc=!ERRORLEVEL!`,
		`exit /B !rc!`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("answer file is missing %q:\n%s", required, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "host") {
		t.Fatalf("answer file unexpectedly refers to a host policy source:\n%s", text)
	}
}

func TestSkuSiPolicyCapabilityRequiresQualifiedWindows11Payload(t *testing.T) {
	qualified := MediaMetadata{
		ProductName: "Windows 11 Pro", Version: "10.0.26100", Architecture: "arm64", InstallationType: "Client",
		SkuSiPolicyAvailable: true,
	}
	if cap := Capabilities(qualified).ApplySkuSiPolicy; !cap.Enabled {
		t.Fatalf("qualified policy capability = %#v", cap)
	}
	missing := qualified
	missing.SkuSiPolicyAvailable = false
	missing.SkuSiPolicyUnavailableWhy = "policy missing from one edition"
	if err := ValidateForMedia(missing, Options{ApplySkuSiPolicy: true}); err == nil || !strings.Contains(err.Error(), "policy missing") {
		t.Fatalf("missing-policy error = %v", err)
	}
	windows10 := qualified
	windows10.ProductName = "Windows 10 Pro"
	if err := ValidateForMedia(windows10, Options{ApplySkuSiPolicy: true}); err == nil || !strings.Contains(err.Error(), "Windows 11") {
		t.Fatalf("Windows 10 policy error = %v", err)
	}
}
