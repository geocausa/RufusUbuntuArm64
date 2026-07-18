package windowsconfig

import (
	"strings"
	"testing"
)

func TestCapabilities(t *testing.T) {
	tests := []struct {
		name           string
		metadata       MediaMetadata
		recognized     bool
		generation     string
		family         string
		architecture   string
		win11Only      bool
		generic        bool
		reasonContains string
	}{
		{
			name:       "Windows 11 ARM64 client",
			metadata:   MediaMetadata{ProductName: "Windows 11 Pro", Version: "10.0", Architecture: "ARM64", InstallationType: "Client"},
			recognized: true, generation: "11", family: "client", architecture: "arm64", win11Only: true, generic: true,
		},
		{
			name:       "Windows 11 amd64 client",
			metadata:   MediaMetadata{ProductName: "Microsoft Windows 11 Enterprise", Version: "10.0.26100", Architecture: "x64", InstallationType: "Client"},
			recognized: true, generation: "11", family: "client", architecture: "amd64", win11Only: true, generic: true,
		},
		{
			name:       "Windows 10 x86 client",
			metadata:   MediaMetadata{ProductName: "Windows 10 Pro", Version: "10.0.19045", Architecture: "x86", InstallationType: "Client"},
			recognized: true, generation: "10", family: "client", architecture: "x86", generic: true,
		},
		{
			name:     "Windows Server without positive generation fails closed",
			metadata: MediaMetadata{ProductName: "Windows Server 2025 Standard", Version: "10.0", Architecture: "amd64", InstallationType: "Server"},
			family:   "server", architecture: "amd64", reasonContains: "version could not be identified",
		},
		{
			name:         "unknown NT 10 media fails closed",
			metadata:     MediaMetadata{Version: "10.0.26100", Architecture: "arm64", InstallationType: "Client"},
			architecture: "arm64", family: "client", reasonContains: "version could not be identified",
		},
		{
			name:       "missing architecture fails closed",
			metadata:   MediaMetadata{ProductName: "Windows 11 Pro", Version: "10.0", InstallationType: "Client"},
			generation: "11", family: "client", reasonContains: "architecture",
		},
		{
			name:         "conflicting generation fails closed",
			metadata:     MediaMetadata{ProductName: "Windows 10 Pro", Version: "11.0", Architecture: "amd64", InstallationType: "Client"},
			architecture: "amd64", family: "client", reasonContains: "conflicting",
		},
		{
			name:       "conflicting family fails closed",
			metadata:   MediaMetadata{ProductName: "Windows Server 2025", Version: "11.0", Architecture: "amd64", InstallationType: "Client"},
			generation: "11", architecture: "amd64", reasonContains: "family metadata is conflicting",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := Capabilities(test.metadata)
			if profile.Recognized != test.recognized {
				t.Fatalf("Recognized = %v, want %v: %#v", profile.Recognized, test.recognized, profile)
			}
			if profile.Generation != test.generation || profile.Family != test.family || profile.Architecture != test.architecture {
				t.Fatalf("normalization = %q/%q/%q, want %q/%q/%q", profile.Generation, profile.Family, profile.Architecture, test.generation, test.family, test.architecture)
			}
			if profile.BypassHardwareChecks.Enabled != test.win11Only || profile.BypassOnlineAccount.Enabled != test.win11Only {
				t.Fatalf("Windows 11-only eligibility = %v/%v, want %v", profile.BypassHardwareChecks.Enabled, profile.BypassOnlineAccount.Enabled, test.win11Only)
			}
			if profile.LocalAccount.Enabled != test.generic || profile.Locale.Enabled != test.generic || profile.LoadDrivers.Enabled != test.generic {
				t.Fatalf("generic eligibility = %v/%v/%v, want %v", profile.LocalAccount.Enabled, profile.Locale.Enabled, profile.LoadDrivers.Enabled, test.generic)
			}
			if test.reasonContains != "" && !strings.Contains(profile.Reason, test.reasonContains) {
				t.Fatalf("Reason = %q, want substring %q", profile.Reason, test.reasonContains)
			}
		})
	}
}

func TestValidateForMedia(t *testing.T) {
	windows11 := MediaMetadata{ProductName: "Windows 11 Pro", Version: "10.0", Architecture: "ARM64", InstallationType: "Client"}
	windows10 := MediaMetadata{ProductName: "Windows 10 Pro", Version: "10.0", Architecture: "amd64", InstallationType: "Client"}
	unknown := MediaMetadata{Version: "10.0", Architecture: "arm64", InstallationType: "Client"}

	if err := ValidateForMedia(windows11, Options{BypassHardwareChecks: true, BypassOnlineAccount: true}); err != nil {
		t.Fatalf("Windows 11 options rejected: %v", err)
	}
	if err := ValidateForMedia(windows10, Options{LocalAccount: "Tester", Locale: "en-GB"}); err != nil {
		t.Fatalf("generic Windows options rejected: %v", err)
	}
	if err := ValidateForMedia(windows10, Options{BypassHardwareChecks: true}); err == nil || !strings.Contains(err.Error(), "Windows 11") {
		t.Fatalf("Windows 10 hardware bypass error = %v, want Windows 11 eligibility error", err)
	}
	if err := ValidateForMedia(unknown, Options{Locale: "en-GB"}); err == nil || !strings.Contains(err.Error(), "could not be identified") {
		t.Fatalf("unknown-media error = %v", err)
	}
	if err := ValidateForMedia(unknown, Options{}); err != nil {
		t.Fatalf("zero options must leave unknown media unchanged: %v", err)
	}
}
