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
	bad := []string{"Administrator", "a/b", "Geo & Co", "percent%name", "caret^name", "bang!name", " leading", "trailing ", strings.Repeat("x", 21), "trailing."}
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
