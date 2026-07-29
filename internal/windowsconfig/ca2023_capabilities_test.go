package windowsconfig

import "testing"

func TestWindowsCA2023CapabilityRequiresQualifiedWindows11ClientAssets(t *testing.T) {
	metadata := MediaMetadata{
		ProductName:             "Windows 11 Pro",
		Version:                 "10.0.26100",
		Architecture:            "arm64",
		InstallationType:        "Client",
		WindowsCA2023Available:  true,
		WindowsCA2023ImageIndex: 2,
	}
	profile := Capabilities(metadata)
	if !profile.UseWindowsCA2023Bootloaders.Enabled {
		t.Fatalf("expected CA 2023 capability, got reason %q", profile.UseWindowsCA2023Bootloaders.Reason)
	}

	metadata.WindowsCA2023Available = false
	metadata.WindowsCA2023UnavailableWhy = "boot.wim _EX set is incomplete"
	profile = Capabilities(metadata)
	if profile.UseWindowsCA2023Bootloaders.Enabled || profile.UseWindowsCA2023Bootloaders.Reason != metadata.WindowsCA2023UnavailableWhy {
		t.Fatalf("expected media-specific refusal, got %+v", profile.UseWindowsCA2023Bootloaders)
	}

	metadata.ProductName = "Windows Server 2025"
	metadata.InstallationType = "Server"
	metadata.WindowsCA2023Available = true
	profile = Capabilities(metadata)
	if profile.UseWindowsCA2023Bootloaders.Enabled {
		t.Fatal("server media must not expose the Windows 11 client CA 2023 option")
	}
}
