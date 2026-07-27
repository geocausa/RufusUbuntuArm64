package windowsconfig

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestGenerateQualityOfLifePolicy(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{QualityOfLife: true})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`pass="specialize"`,
		`pass="oobeSystem"`,
		`DisableFileSyncNGSC`,
		`OneDriveSetup.exe`,
		`*Outlook*`,
		`*Teams*`,
		`HiberbootEnabled`,
		`TurnOffWindowsCopilot`,
		`DisableWindowsConsumerFeatures`,
		`AllowNewsAndInterests`,
		`ConfigureChatAutoInstall`,
		`DisableCloudOptimizedContent`,
		`HideFirstRunExperience`,
		`VisiblePlaces`,
		upstreamVisiblePlacesBase64,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Count(text, "<FirstLogonCommands>") != 1 {
		t.Fatalf("expected exactly one FirstLogonCommands section:\n%s", text)
	}
	ordered := []string{"DisableFileSyncNGSC", "OneDriveSetup.exe", "*Outlook*", "*Teams*"}
	previous := -1
	for _, value := range ordered {
		current := strings.Index(text, value)
		if current <= previous {
			t.Fatalf("specialize command %q is out of order in:\n%s", value, text)
		}
		previous = current
	}
	var parsed any
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestQualityOfLifeGenerationIsDeterministic(t *testing.T) {
	options := Options{QualityOfLife: true, LocalAccount: "geoca"}
	first, err := Generate("amd64", options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate("amd64", options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Quality of Life answer-file generation is not deterministic")
	}
	if strings.Count(string(first), "<FirstLogonCommands>") != 1 {
		t.Fatalf("local-account and Quality of Life commands were split across sections:\n%s", first)
	}
	if strings.Index(string(first), "logonpasswordchg") > strings.Index(string(first), "HiberbootEnabled") {
		t.Fatalf("local-account safety commands must precede Quality of Life commands:\n%s", first)
	}
}

func TestQualityOfLifeCapabilityIsClientOnly(t *testing.T) {
	client := MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0",
		Architecture:     "arm64",
		InstallationType: "Client",
	}
	clientProfile := Capabilities(client)
	if !clientProfile.Recognized || !clientProfile.QualityOfLife.Enabled {
		t.Fatalf("client Quality of Life capability unavailable: %#v", clientProfile)
	}
	if err := ValidateForMedia(client, Options{QualityOfLife: true}); err != nil {
		t.Fatal(err)
	}

	server := MediaMetadata{
		ProductName:      "Windows Server 2025",
		Version:          "11.0",
		Architecture:     "arm64",
		InstallationType: "Server",
	}
	serverProfile := Capabilities(server)
	if !serverProfile.Recognized || serverProfile.QualityOfLife.Enabled {
		t.Fatalf("server Quality of Life capability was not refused: %#v", serverProfile)
	}
	if err := ValidateForMedia(server, Options{QualityOfLife: true}); err == nil || !strings.Contains(err.Error(), "Quality of Life") {
		t.Fatalf("server Quality of Life validation error=%v", err)
	}
}

func TestQualityOfLifeRemainsOptIn(t *testing.T) {
	data, err := Generate("arm64", Options{ReduceDataCollection: true})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, absent := range []string{"OneDriveSetup.exe", "*Outlook*", "*Teams*", "TurnOffWindowsCopilot", "VisiblePlaces"} {
		if strings.Contains(text, absent) {
			t.Fatalf("Quality of Life behavior %q appeared without opt-in:\n%s", absent, text)
		}
	}
}
