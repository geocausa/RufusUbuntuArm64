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

func TestSilentInstallCapabilityRequiresExactMediaEvidence(t *testing.T) {
	base := MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "ARM64",
		InstallationType: "Client",
		ImageCount:       2,
		Images: []WindowsImage{
			{Index: 1, Name: "Windows 11 Home", DefaultLanguage: "en-GB"},
			{Index: 2, Name: "Windows 11 Pro", DefaultLanguage: "en-GB"},
		},
		BootLanguage: "en-GB",
	}
	if capability := Capabilities(base).SilentInstall; !capability.Enabled {
		t.Fatalf("qualified silent install disabled: %#v", capability)
	}
	for name, mutate := range map[string]func(*MediaMetadata){
		"existing answer": func(m *MediaMetadata) { m.ExistingUnattendPath = "autounattend.xml" },
		"missing images":  func(m *MediaMetadata) { m.Images = nil },
		"duplicate index": func(m *MediaMetadata) { m.Images[1].Index = 1 },
		"missing name":    func(m *MediaMetadata) { m.Images[0].Name = "" },
		"boot language":   func(m *MediaMetadata) { m.BootLanguage = "" },
		"Windows 10":      func(m *MediaMetadata) { m.ProductName = "Windows 10 Pro" },
	} {
		t.Run(name, func(t *testing.T) {
			metadata := base
			metadata.Images = append([]WindowsImage(nil), base.Images...)
			mutate(&metadata)
			if capability := Capabilities(metadata).SilentInstall; capability.Enabled || capability.Reason == "" {
				t.Fatalf("unqualified silent install accepted: %#v", capability)
			}
		})
	}
}

func TestValidateForMediaSilentInstall(t *testing.T) {
	metadata := MediaMetadata{
		ProductName: "Windows 11 Pro", Version: "10.0.26100", Architecture: "ARM64", InstallationType: "Client",
		ImageCount: 1, Images: []WindowsImage{{Index: 4, Name: "Windows 11 Pro"}}, BootLanguage: "en-GB",
	}
	options := Options{
		LocalAccount: "Tester", ReduceDataCollection: true, SilentInstall: true,
		InstallImageIndex: 4, Locale: "en-GB", TimeZone: "GMT Standard Time",
	}
	if err := ValidateForMedia(metadata, options); err != nil {
		t.Fatal(err)
	}
	metadata.ExistingUnattendPath = "sources/$OEM$/$$/Panther/unattend.xml"
	if err := ValidateForMedia(metadata, options); err == nil || !strings.Contains(err.Error(), "already contains") {
		t.Fatalf("existing-answer error=%v", err)
	}
}

func TestWindowsToGoCapabilityRequiresExactARM64ImageEvidence(t *testing.T) {
	base := MediaMetadata{
		ProductName: "Windows 11 Pro", Version: "10.0.26100", Architecture: "ARM64", InstallationType: "Client",
		ImageCount: 2, Images: []WindowsImage{
			{Index: 1, Name: "Windows 11 Home", DefaultLanguage: "en-GB", TotalBytes: 24 * 1024 * 1024 * 1024},
			{Index: 3, Name: "Windows 11 Pro", DefaultLanguage: "en-GB", TotalBytes: 25 * 1024 * 1024 * 1024},
		},
	}
	if capability := Capabilities(base).WindowsToGo; !capability.Enabled {
		t.Fatalf("qualified Windows To Go disabled: %#v", capability)
	}
	for name, mutate := range map[string]func(*MediaMetadata){
		"Windows 10":       func(m *MediaMetadata) { m.ProductName = "Windows 10 Pro" },
		"amd64":            func(m *MediaMetadata) { m.Architecture = "amd64" },
		"server":           func(m *MediaMetadata) { m.ProductName, m.InstallationType = "Windows Server 2025", "Server" },
		"missing images":   func(m *MediaMetadata) { m.Images = nil },
		"image count":      func(m *MediaMetadata) { m.ImageCount = 3 },
		"duplicate index":  func(m *MediaMetadata) { m.Images[1].Index = 1 },
		"missing name":     func(m *MediaMetadata) { m.Images[0].Name = "" },
		"missing size":     func(m *MediaMetadata) { m.Images[0].TotalBytes = 0 },
		"missing language": func(m *MediaMetadata) { m.Images[0].DefaultLanguage = "" },
		"bad language":     func(m *MediaMetadata) { m.Images[0].DefaultLanguage = "en GB" },
	} {
		t.Run(name, func(t *testing.T) {
			metadata := base
			metadata.Images = append([]WindowsImage(nil), base.Images...)
			mutate(&metadata)
			capability := Capabilities(metadata).WindowsToGo
			if capability.Enabled || capability.Reason == "" {
				t.Fatalf("unqualified Windows To Go accepted: %#v", capability)
			}
		})
	}
}
