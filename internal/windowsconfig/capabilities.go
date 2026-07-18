package windowsconfig

import (
	"fmt"
	"strconv"
	"strings"
)

// MediaMetadata contains the Windows identity facts obtained from inspected
// installation media. Empty or conflicting facts deliberately produce a
// fail-closed capability profile.
type MediaMetadata struct {
	ProductName      string
	Version          string
	Architecture     string
	InstallationType string
}

// OptionCapability explains whether one setup option is safe for the detected
// media. Reason is populated whenever Enabled is false.
type OptionCapability struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

// CapabilityProfile is the normalized eligibility decision shared by the CLI,
// graphical interface, and answer-file generator.
type CapabilityProfile struct {
	Recognized           bool             `json:"recognized"`
	Generation           string           `json:"generation,omitempty"`
	Family               string           `json:"family,omitempty"`
	Architecture         string           `json:"architecture,omitempty"`
	Reason               string           `json:"reason,omitempty"`
	BypassHardwareChecks OptionCapability `json:"bypass_hardware_checks"`
	BypassOnlineAccount  OptionCapability `json:"bypass_online_account"`
	LocalAccount         OptionCapability `json:"local_account"`
	ReduceDataCollection OptionCapability `json:"reduce_data_collection"`
	DisableBitLocker     OptionCapability `json:"disable_bitlocker"`
	LoadDrivers          OptionCapability `json:"load_drivers"`
	Locale               OptionCapability `json:"locale"`
	TimeZone             OptionCapability `json:"time_zone"`
}

// Capabilities derives a conservative setup-option profile. Windows 11-only
// workarounds are enabled only when client Windows 11 media is positively
// identified. Generic documented unattend settings remain available for
// positively identified Windows client or server installation media.
func Capabilities(metadata MediaMetadata) CapabilityProfile {
	arch := normalizeArchitecture(metadata.Architecture)
	generation, generationConflict := detectGeneration(metadata.ProductName, metadata.Version)
	family, familyConflict := detectFamily(metadata.ProductName, metadata.InstallationType)

	profile := CapabilityProfile{
		Generation:   generation,
		Family:       family,
		Architecture: arch,
	}
	if arch == "" {
		return disabledProfile(profile, "Windows architecture is missing or unsupported")
	}
	if generationConflict {
		return disabledProfile(profile, "Windows version metadata is conflicting")
	}
	if familyConflict {
		return disabledProfile(profile, "Windows edition-family metadata is conflicting")
	}
	if generation == "" {
		return disabledProfile(profile, "Windows version could not be identified")
	}
	if family == "" {
		return disabledProfile(profile, "Windows client or server family could not be identified")
	}

	profile.Recognized = true
	generic := OptionCapability{Enabled: true}
	profile.LocalAccount = generic
	profile.ReduceDataCollection = generic
	profile.DisableBitLocker = generic
	profile.LoadDrivers = generic
	profile.Locale = generic
	profile.TimeZone = generic

	if family == "client" && generation == "11" {
		profile.BypassHardwareChecks = generic
		profile.BypassOnlineAccount = generic
	} else {
		reason := "Available only for positively identified Windows 11 client media"
		profile.BypassHardwareChecks = OptionCapability{Reason: reason}
		profile.BypassOnlineAccount = OptionCapability{Reason: reason}
	}
	return profile
}

// ValidateForMedia rejects selected options that are not eligible for the
// inspected media. Syntax validation remains the responsibility of Validate.
func ValidateForMedia(metadata MediaMetadata, options Options) error {
	if err := Validate(options); err != nil {
		return err
	}
	if !options.Enabled() {
		return nil
	}
	profile := Capabilities(metadata)
	if !profile.Recognized {
		return fmt.Errorf("windows setup options are unavailable: %s", profile.Reason)
	}
	checks := []struct {
		selected bool
		name     string
		cap      OptionCapability
	}{
		{options.BypassHardwareChecks, "hardware-check bypass", profile.BypassHardwareChecks},
		{options.BypassOnlineAccount, "online-account bypass", profile.BypassOnlineAccount},
		{strings.TrimSpace(options.LocalAccount) != "", "local account", profile.LocalAccount},
		{options.ReduceDataCollection, "reduced data collection", profile.ReduceDataCollection},
		{options.DisableBitLocker, "BitLocker suppression", profile.DisableBitLocker},
		{options.LoadDrivers, "driver loading", profile.LoadDrivers},
		{strings.TrimSpace(options.Locale) != "", "locale", profile.Locale},
		{strings.TrimSpace(options.TimeZone) != "", "time zone", profile.TimeZone},
	}
	for _, check := range checks {
		if check.selected && !check.cap.Enabled {
			return fmt.Errorf("windows setup option %s is unavailable: %s", check.name, check.cap.Reason)
		}
	}
	return nil
}

func disabledProfile(profile CapabilityProfile, reason string) CapabilityProfile {
	profile.Reason = reason
	disabled := OptionCapability{Reason: reason}
	profile.BypassHardwareChecks = disabled
	profile.BypassOnlineAccount = disabled
	profile.LocalAccount = disabled
	profile.ReduceDataCollection = disabled
	profile.DisableBitLocker = disabled
	profile.LoadDrivers = disabled
	profile.Locale = disabled
	profile.TimeZone = disabled
	return profile
}

func detectGeneration(productName, version string) (string, bool) {
	fromName := ""
	name := strings.ToLower(productName)
	if strings.Contains(name, "windows 11") {
		fromName = "11"
	} else if strings.Contains(name, "windows 10") {
		fromName = "10"
	}
	fromVersion := ""
	majorText := strings.SplitN(strings.TrimSpace(version), ".", 2)[0]
	if major, err := strconv.Atoi(majorText); err == nil {
		switch {
		case major >= 11:
			fromVersion = "11"
		case major == 10:
			// Windows 10 and 11 both report NT 10.0, so this is intentionally
			// insufficient to distinguish them without a product-name signal.
			fromVersion = "10-or-11"
		}
	}
	if fromName != "" {
		if fromVersion != "" && fromVersion != "10-or-11" && fromVersion != fromName {
			return "", true
		}
		return fromName, false
	}
	if fromVersion == "10-or-11" {
		return "", false
	}
	return fromVersion, false
}

func detectFamily(productName, installationType string) (string, bool) {
	name := strings.ToLower(productName)
	typeName := strings.ToLower(installationType)
	server := strings.Contains(name, "server") || strings.Contains(typeName, "server")
	client := strings.Contains(typeName, "client") || strings.Contains(typeName, "workstation") ||
		(strings.Contains(name, "windows") && !strings.Contains(name, "server"))
	if server && client {
		return "", true
	}
	if server {
		return "server", false
	}
	if client {
		return "client", false
	}
	return "", false
}
