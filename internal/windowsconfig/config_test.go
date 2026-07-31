package windowsconfig

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestGenerateAllOptions(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{
		BypassHardwareChecks: true,
		BypassOnlineAccount:  true,
		LocalAccount:         "Geo Co",
		ReduceDataCollection: true,
		DisableBitLocker:     true,
		Locale:               "en-GB",
		TimeZone:             "GMT Standard Time",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"BypassTPMCheck", "BypassNRO", "ProtectYourPC", "PreventDeviceEncryption", "Geo Co", "processorArchitecture=\"arm64\"", "<InputLocale>en-GB</InputLocale>", "<TimeZone>GMT Standard Time</TimeZone>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	var parsed any
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateZeroOptions(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatalf("expected nil, got %q", data)
	}
}

func TestValidateUsername(t *testing.T) {
	bad := []string{
		"Administrator",
		"ADMINISTRATEUR",
		"JÄRJESTELMÄNVALVOJA",
		"Rendszergazda",
		"Administrador",
		"АДМИНИСТРАТОР",
		"Administratör",
		"a/b",
		"Geo & Co",
		"percent%name",
		"caret^name",
		"bang!name",
		" leading",
		"trailing ",
		strings.Repeat("x", 21),
		"trailing.",
	}
	for _, name := range bad {
		if err := Validate(Options{LocalAccount: name}); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if err := Validate(Options{LocalAccount: "geoca", Locale: "en-GB", TimeZone: "GMT Standard Time"}); err != nil {
		t.Fatal(err)
	}
	for _, options := range []Options{{Locale: "bad_locale"}, {TimeZone: "Bad<Zone"}} {
		if err := Validate(options); err == nil {
			t.Fatalf("accepted invalid regional settings: %#v", options)
		}
	}
}

func TestGenerateDriverAutoload(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{LoadDrivers: true})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`pass="windowsPE"`,
		`Microsoft-Windows-Setup`,
		`RUFUSARM64.DRV`,
		`for /R`,
		`drvload`,
		`processorArchitecture="arm64"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	var parsed any
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateX86AnswerFile(t *testing.T) {
	data, err := Generate("x86 UEFI", Options{BypassHardwareChecks: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `processorArchitecture="x86"`) {
		t.Fatalf("x86 processor architecture missing from:\n%s", data)
	}
}

func TestGenerateGuardedSilentInstall(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{
		LocalAccount:         "Tester",
		ReduceDataCollection: true,
		SilentInstall:        true,
		InstallImageIndex:    3,
		BootLanguage:         "en-GB",
		Locale:               "en-GB",
		TimeZone:             "GMT Standard Time",
		DisableBitLocker:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, `\"`) {
		t.Fatalf("silent answer file contains escaped XML attribute quotes:\n%s", text)
	}
	for _, want := range []string{
		"<AcceptEula>true</AcceptEula>",
		"<DiskID>1</DiskID>",
		"<PartitionID>2</PartitionID>",
		"<Label>RUFUS_BOOT</Label>",
		"<DiskID>0</DiskID>",
		"<WillWipeDisk>true</WillWipeDisk>",
		"<Type>EFI</Type><Size>260</Size>",
		"<Type>MSR</Type><Size>16</Size>",
		"<Key>/IMAGE/INDEX</Key><Value>3</Value>",
		"<InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>",
		"<UILanguage>en-GB</UILanguage>",
		"<HideEULAPage>true</HideEULAPage>",
		"<HideOnlineAccountScreens>true</HideOnlineAccountScreens>",
		"<HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>",
		"<ProtectYourPC>3</ProtectYourPC>",
		"<DisableEncryptedDiskProvisioning>true</DisableEncryptedDiskProvisioning>",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	var parsed any
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestSilentInstallPrerequisitesFailClosed(t *testing.T) {
	base := Options{
		LocalAccount:         "Tester",
		ReduceDataCollection: true,
		SilentInstall:        true,
		InstallImageIndex:    1,
		BootLanguage:         "en-GB",
		Locale:               "en-GB",
		TimeZone:             "GMT Standard Time",
	}
	for name, mutate := range map[string]func(*Options){
		"account":       func(o *Options) { o.LocalAccount = "" },
		"privacy":       func(o *Options) { o.ReduceDataCollection = false },
		"locale":        func(o *Options) { o.Locale = "" },
		"time zone":     func(o *Options) { o.TimeZone = "" },
		"image index":   func(o *Options) { o.InstallImageIndex = 0 },
		"boot language": func(o *Options) { o.BootLanguage = "" },
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if _, err := Generate("ARM64 UEFI", options); err == nil {
				t.Fatal("incomplete silent-install request was accepted")
			}
		})
	}
}
