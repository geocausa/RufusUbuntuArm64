package windowsconfig

import (
	"fmt"
	"strconv"
	"strings"
)

// WindowsImage binds one selectable installation image to its exact WIM index.
// Names are disclosure only; destructive silent installation always uses Index.
type WindowsImage struct {
	Index           int    `json:"index"`
	Name            string `json:"name"`
	DefaultLanguage string `json:"default_language,omitempty"`
	TotalBytes      uint64 `json:"total_bytes,omitempty"`
}

// MediaMetadata contains the Windows identity facts obtained from inspected
// installation media. Empty or conflicting facts deliberately produce a
// fail-closed capability profile. Images retains exact WIM indexes while
// ImageCount and EditionNames provide bounded user-facing disclosure.
type MediaMetadata struct {
	ProductName                 string         `json:"product_name,omitempty"`
	Version                     string         `json:"version,omitempty"`
	Architecture                string         `json:"architecture,omitempty"`
	InstallationType            string         `json:"installation_type,omitempty"`
	ImageCount                  int            `json:"image_count,omitempty"`
	EditionNames                []string       `json:"edition_names,omitempty"`
	Images                      []WindowsImage `json:"images,omitempty"`
	BootLanguage                string         `json:"boot_language,omitempty"`
	ExistingUnattendPath        string         `json:"existing_unattend_path,omitempty"`
	SkuSiPolicyAvailable        bool           `json:"sku_si_policy_available"`
	SkuSiPolicyUnavailableWhy   string         `json:"sku_si_policy_unavailable_reason,omitempty"`
	WindowsCA2023Available      bool           `json:"windows_ca_2023_available"`
	WindowsCA2023UnavailableWhy string         `json:"windows_ca_2023_unavailable_reason,omitempty"`
	WindowsCA2023ImageIndex     int            `json:"windows_ca_2023_image_index,omitempty"`
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
	Recognized                  bool             `json:"recognized"`
	Generation                  string           `json:"generation,omitempty"`
	Family                      string           `json:"family,omitempty"`
	Architecture                string           `json:"architecture,omitempty"`
	Reason                      string           `json:"reason,omitempty"`
	BypassHardwareChecks        OptionCapability `json:"bypass_hardware_checks"`
	BypassOnlineAccount         OptionCapability `json:"bypass_online_account"`
	LocalAccount                OptionCapability `json:"local_account"`
	ReduceDataCollection        OptionCapability `json:"reduce_data_collection"`
	DisableBitLocker            OptionCapability `json:"disable_bitlocker"`
	LoadDrivers                 OptionCapability `json:"load_drivers"`
	QualityOfLife               OptionCapability `json:"quality_of_life"`
	ApplySkuSiPolicy            OptionCapability `json:"apply_sku_si_policy"`
	UseWindowsCA2023Bootloaders OptionCapability `json:"use_windows_ca_2023_bootloaders"`
	SilentInstall               OptionCapability `json:"silent_install"`
	Locale                      OptionCapability `json:"locale"`
	TimeZone                    OptionCapability `json:"time_zone"`
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

	if family == "client" {
		profile.QualityOfLife = generic
	} else {
		profile.QualityOfLife = OptionCapability{Reason: "Available only for positively identified Windows client media"}
	}

	if family == "client" && generation == "11" {
		profile.BypassHardwareChecks = generic
		profile.BypassOnlineAccount = generic
		if metadata.SkuSiPolicyAvailable {
			profile.ApplySkuSiPolicy = generic
		} else {
			reason := strings.TrimSpace(metadata.SkuSiPolicyUnavailableWhy)
			if reason == "" {
				reason = "SkuSiPolicy.p7b was not found in every Windows installation image"
			}
			profile.ApplySkuSiPolicy = OptionCapability{Reason: reason}
		}
		if metadata.WindowsCA2023Available {
			profile.UseWindowsCA2023Bootloaders = generic
		} else {
			reason := strings.TrimSpace(metadata.WindowsCA2023UnavailableWhy)
			if reason == "" {
				reason = "A complete, architecture-matched Windows UEFI CA 2023 bootloader set was not proven in boot.wim"
			}
			profile.UseWindowsCA2023Bootloaders = OptionCapability{Reason: reason}
		}
	} else {
		reason := "Available only for positively identified Windows 11 client media"
		profile.BypassHardwareChecks = OptionCapability{Reason: reason}
		profile.BypassOnlineAccount = OptionCapability{Reason: reason}
		profile.ApplySkuSiPolicy = OptionCapability{Reason: reason}
		profile.UseWindowsCA2023Bootloaders = OptionCapability{Reason: reason}
	}
	profile.SilentInstall = silentInstallCapability(metadata, profile)
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
		{options.QualityOfLife, "Quality of Life policy", profile.QualityOfLife},
		{options.ApplySkuSiPolicy, "SkuSiPolicy deployment", profile.ApplySkuSiPolicy},
		{options.SilentInstall, "silent installation", profile.SilentInstall},
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
	profile.QualityOfLife = disabled
	profile.ApplySkuSiPolicy = disabled
	profile.UseWindowsCA2023Bootloaders = disabled
	profile.SilentInstall = disabled
	profile.Locale = disabled
	profile.TimeZone = disabled
	return profile
}

func silentInstallCapability(metadata MediaMetadata, profile CapabilityProfile) OptionCapability {
	const genericReason = "Available only for positively identified Windows 11 client media"
	if !profile.Recognized || profile.Generation != "11" || profile.Family != "client" {
		return OptionCapability{Reason: genericReason}
	}
	if strings.TrimSpace(metadata.ExistingUnattendPath) != "" {
		return OptionCapability{Reason: "The selected ISO already contains an unattended-setup file at " + metadata.ExistingUnattendPath}
	}
	if len(metadata.Images) == 0 || len(metadata.Images) != metadata.ImageCount {
		return OptionCapability{Reason: "Exact Windows installation-image indexes were not proven"}
	}
	seen := make(map[int]struct{}, len(metadata.Images))
	for _, image := range metadata.Images {
		if image.Index <= 0 || image.Index > 256 || strings.TrimSpace(image.Name) == "" {
			return OptionCapability{Reason: "Windows installation-image metadata is incomplete"}
		}
		if _, duplicate := seen[image.Index]; duplicate {
			return OptionCapability{Reason: "Windows installation-image indexes are duplicated"}
		}
		seen[image.Index] = struct{}{}
	}
	if !validLocale.MatchString(strings.TrimSpace(metadata.BootLanguage)) {
		return OptionCapability{Reason: "The Windows Setup boot language was not proven from boot.wim"}
	}
	return OptionCapability{Enabled: true}
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
