package windowsconfig

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestGenerateWindowsToGoIncludesRequiredSANPolicyAndFirstBootChoices(t *testing.T) {
	options := Options{
		BypassOnlineAccount:  true,
		LocalAccount:         "PortableUser",
		ReduceDataCollection: true,
		QualityOfLife:        true,
		Locale:               "en-GB",
		TimeZone:             "GMT Standard Time",
	}
	first, err := GenerateWindowsToGo("ARM64 UEFI", options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateWindowsToGo("arm64", options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Windows To Go answer-file generation is not deterministic")
	}
	text := string(first)
	for _, want := range []string{
		`pass="offlineServicing"`, `<SanPolicy>4</SanPolicy>`,
		`pass="specialize"`, `BypassNRO`, `AllowTelemetry`, `DisableFileSyncNGSC`,
		`pass="oobeSystem"`, `PortableUser`, `<ProtectYourPC>3</ProtectYourPC>`,
		`<InputLocale>en-GB</InputLocale>`, `<TimeZone>GMT Standard Time</TimeZone>`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Windows To Go answer file is missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{
		`pass="windowsPE"`, `DiskConfiguration`, `ImageInstall`, `BypassTPMCheck`,
		`PreventDeviceEncryption`, `SkuSiPolicy.p7b`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Windows To Go answer file contains installer-only setting %q:\n%s", forbidden, text)
		}
	}
	var parsed any
	if err := xml.Unmarshal(first, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateWindowsToGoWithoutOptionalChoicesRemainsNarrow(t *testing.T) {
	data, err := GenerateWindowsToGo("arm64", Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `<SanPolicy>4</SanPolicy>`) {
		t.Fatalf("required SAN policy missing:\n%s", text)
	}
	for _, forbidden := range []string{"specialize", "oobeSystem", "windowsPE", "LocalAccount"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("zero-option Windows To Go answer file contains %q:\n%s", forbidden, text)
		}
	}
}

func TestValidateWindowsToGoRejectsInstallerOnlyChoices(t *testing.T) {
	for name, options := range map[string]Options{
		"hardware":  {BypassHardwareChecks: true},
		"bitlocker": {DisableBitLocker: true},
		"drivers":   {LoadDrivers: true},
		"policy":    {ApplySkuSiPolicy: true},
		"silent":    {SilentInstall: true},
		"index":     {InstallImageIndex: 3},
		"bootlang":  {BootLanguage: "en-GB"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateWindowsToGo(options); err == nil {
				t.Fatalf("unsupported Windows To Go choice was accepted: %#v", options)
			}
		})
	}
	if err := ValidateWindowsToGo(Options{
		BypassOnlineAccount: true, LocalAccount: "PortableUser",
		ReduceDataCollection: true, QualityOfLife: true,
		Locale: "en-GB", TimeZone: "GMT Standard Time",
	}); err != nil {
		t.Fatalf("supported Windows To Go choices were rejected: %v", err)
	}
}
