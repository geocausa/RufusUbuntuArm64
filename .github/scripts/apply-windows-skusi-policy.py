#!/usr/bin/env python3
"""Apply the bounded Rufus 4.15 SkuSiPolicy setup-policy tranche."""

from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if old in text:
        text = text.replace(old, new, 1)
    elif new not in text:
        raise SystemExit(f"missing {label} anchor in {path}")
    file.write_text(text, encoding="utf-8")


def add_before(path: str, marker: str, addition: str, label: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if addition.strip() in text:
        return
    if marker not in text:
        raise SystemExit(f"missing {label} marker in {path}")
    file.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")


def write(path: str, content: str) -> None:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content, encoding="utf-8")


# windowsconfig.Options and answer-file generation.
replace_once(
    "internal/windowsconfig/config.go",
    "\tQualityOfLife        bool\n\tLocale               string\n",
    "\tQualityOfLife        bool\n\tApplySkuSiPolicy      bool\n\tLocale               string\n",
    "Options field",
)
replace_once(
    "internal/windowsconfig/config.go",
    "return o.BypassHardwareChecks || o.BypassOnlineAccount || strings.TrimSpace(o.LocalAccount) != \"\" || o.ReduceDataCollection || o.DisableBitLocker || o.LoadDrivers || o.QualityOfLife || strings.TrimSpace(o.Locale) != \"\" || strings.TrimSpace(o.TimeZone) != \"\"",
    "return o.BypassHardwareChecks || o.BypassOnlineAccount || strings.TrimSpace(o.LocalAccount) != \"\" || o.ReduceDataCollection || o.DisableBitLocker || o.LoadDrivers || o.QualityOfLife || o.ApplySkuSiPolicy || strings.TrimSpace(o.Locale) != \"\" || strings.TrimSpace(o.TimeZone) != \"\"",
    "Options Enabled",
)
replace_once(
    "internal/windowsconfig/config.go",
    "\tshellComponent := o.BypassOnlineAccount || o.ReduceDataCollection || strings.TrimSpace(o.LocalAccount) != \"\" || o.QualityOfLife || timeZone != \"\"\n",
    "\tshellComponent := o.BypassOnlineAccount || o.ReduceDataCollection || strings.TrimSpace(o.LocalAccount) != \"\" || o.QualityOfLife || o.ApplySkuSiPolicy || timeZone != \"\"\n",
    "oobe component selection",
)
replace_once(
    "internal/windowsconfig/config.go",
    "\t\t\tif username != \"\" || o.QualityOfLife {\n",
    "\t\t\tif username != \"\" || o.QualityOfLife || o.ApplySkuSiPolicy {\n",
    "first-logon selection",
)
replace_once(
    "internal/windowsconfig/config.go",
    '''\t\t\t\tif o.QualityOfLife {
\t\t\t\t\tfor _, command := range qualityOfLifeFirstLogonCommands() {
\t\t\t\t\t\tfmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\\\"add\\\"><Order>%d</Order><CommandLine>%s</CommandLine></SynchronousCommand>\\n", order, escapeText(command))
\t\t\t\t\t\torder++
\t\t\t\t\t}
\t\t\t\t}
''',
    '''\t\t\t\tif o.ApplySkuSiPolicy {
\t\t\t\t\t// Use the installed system's own policy, matching Rufus's safety
\t\t\t\t\t// boundary. Delayed expansion preserves the copy result while the
\t\t\t\t\t// ESP is unmounted even when copying fails.
\t\t\t\t\tcommand := `cmd.exe /V:ON /C "mountvol S: /S && (copy /Y %WINDIR%\\System32\\SecureBootUpdates\\SkuSiPolicy.p7b S:\\EFI\\Microsoft\\Boot\\SkuSiPolicy.p7b & set rc=!ERRORLEVEL! & mountvol S: /D & exit /B !rc!)"`
\t\t\t\t\tfmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\\\"add\\\"><Order>%d</Order><CommandLine>%s</CommandLine><Description>Apply the installed Windows SkuSiPolicy to the EFI System Partition</Description></SynchronousCommand>\\n", order, escapeText(command))
\t\t\t\t\torder++
\t\t\t\t}
\t\t\t\tif o.QualityOfLife {
\t\t\t\t\tfor _, command := range qualityOfLifeFirstLogonCommands() {
\t\t\t\t\t\tfmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\\\"add\\\"><Order>%d</Order><CommandLine>%s</CommandLine></SynchronousCommand>\\n", order, escapeText(command))
\t\t\t\t\t\torder++
\t\t\t\t\t}
\t\t\t\t}
''',
    "SkuSiPolicy first-logon command",
)

# Capability model.
replace_once(
    "internal/windowsconfig/capabilities.go",
    "\tEditionNames     []string `json:\"edition_names,omitempty\"`\n",
    "\tEditionNames             []string `json:\"edition_names,omitempty\"`\n\tSkuSiPolicyAvailable      bool     `json:\"sku_si_policy_available\"`\n\tSkuSiPolicyUnavailableWhy string   `json:\"sku_si_policy_unavailable_reason,omitempty\"`\n",
    "MediaMetadata SkuSiPolicy fields",
)
replace_once(
    "internal/windowsconfig/capabilities.go",
    "\tQualityOfLife        OptionCapability `json:\"quality_of_life\"`\n\tLocale               OptionCapability `json:\"locale\"`\n",
    "\tQualityOfLife        OptionCapability `json:\"quality_of_life\"`\n\tApplySkuSiPolicy      OptionCapability `json:\"apply_sku_si_policy\"`\n\tLocale               OptionCapability `json:\"locale\"`\n",
    "CapabilityProfile SkuSiPolicy field",
)
replace_once(
    "internal/windowsconfig/capabilities.go",
    '''\tif family == "client" && generation == "11" {
\t\tprofile.BypassHardwareChecks = generic
\t\tprofile.BypassOnlineAccount = generic
\t} else {
\t\treason := "Available only for positively identified Windows 11 client media"
\t\tprofile.BypassHardwareChecks = OptionCapability{Reason: reason}
\t\tprofile.BypassOnlineAccount = OptionCapability{Reason: reason}
\t}
''',
    '''\tif family == "client" && generation == "11" {
\t\tprofile.BypassHardwareChecks = generic
\t\tprofile.BypassOnlineAccount = generic
\t\tif metadata.SkuSiPolicyAvailable {
\t\t\tprofile.ApplySkuSiPolicy = generic
\t\t} else {
\t\t\treason := strings.TrimSpace(metadata.SkuSiPolicyUnavailableWhy)
\t\t\tif reason == "" {
\t\t\t\treason = "SkuSiPolicy.p7b was not found in every Windows installation image"
\t\t\t}
\t\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}
\t\t}
\t} else {
\t\treason := "Available only for positively identified Windows 11 client media"
\t\tprofile.BypassHardwareChecks = OptionCapability{Reason: reason}
\t\tprofile.BypassOnlineAccount = OptionCapability{Reason: reason}
\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}
\t}
''',
    "Windows 11 SkuSiPolicy capability",
)
replace_once(
    "internal/windowsconfig/capabilities.go",
    "\t\t{options.QualityOfLife, \"Quality of Life policy\", profile.QualityOfLife},\n",
    "\t\t{options.QualityOfLife, \"Quality of Life policy\", profile.QualityOfLife},\n\t\t{options.ApplySkuSiPolicy, \"SkuSiPolicy deployment\", profile.ApplySkuSiPolicy},\n",
    "ValidateForMedia SkuSiPolicy check",
)
replace_once(
    "internal/windowsconfig/capabilities.go",
    "\tprofile.QualityOfLife = disabled\n\tprofile.Locale = disabled\n",
    "\tprofile.QualityOfLife = disabled\n\tprofile.ApplySkuSiPolicy = disabled\n\tprofile.Locale = disabled\n",
    "disabled profile SkuSiPolicy",
)

# WIM feature probing.
write(
    "internal/windowsmedia/wimfeatures.go",
    r'''//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const skuSiPolicyWIMPath = "/Windows/System32/SecureBootUpdates/SkuSiPolicy.p7b"

// InspectWIMSetupMetadata combines bounded WIM identity metadata with the
// capability evidence needed by optional Windows setup policies.
func InspectWIMSetupMetadata(ctx context.Context, imagePath string) (windowsconfig.MediaMetadata, error) {
	metadata, err := InspectWIMMetadata(ctx, imagePath)
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	if strings.EqualFold(filepath.Ext(imagePath), ".swm") {
		metadata.SkuSiPolicyUnavailableWhy = "SkuSiPolicy probing is not yet qualified for split SWM installation payloads"
		return metadata, nil
	}
	available, err := inspectWIMPathInEveryImage(ctx, imagePath, metadata.ImageCount, skuSiPolicyWIMPath)
	if err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect SkuSiPolicy capability: %w", err)
	}
	metadata.SkuSiPolicyAvailable = available
	if !available {
		metadata.SkuSiPolicyUnavailableWhy = "SkuSiPolicy.p7b was not found in every Windows installation image"
	}
	return metadata, nil
}

func inspectWIMPathInEveryImage(ctx context.Context, imagePath string, imageCount int, wimPath string) (bool, error) {
	if imageCount <= 0 || imageCount > maxWIMImages {
		return false, fmt.Errorf("invalid WIM image count %d", imageCount)
	}
	wimlib, err := wimlibExecutable()
	if err != nil {
		return false, err
	}
	for index := 1; index <= imageCount; index++ {
		available, err := inspectWIMPath(ctx, wimlib, imagePath, index, wimPath)
		if err != nil {
			return false, err
		}
		if !available {
			return false, nil
		}
	}
	return true, nil
}

func inspectWIMPath(ctx context.Context, executable, imagePath string, imageIndex int, wimPath string) (bool, error) {
	if strings.TrimSpace(executable) == "" || strings.TrimSpace(imagePath) == "" || imageIndex <= 0 || !strings.HasPrefix(wimPath, "/") {
		return false, errors.New("invalid WIM path inspection request")
	}
	stdout := NewBoundedBuffer(256 * 1024)
	stderr := NewBoundedBuffer(64 * 1024)
	command := exec.CommandContext(ctx, executable, "dir", imagePath, strconv.Itoa(imageIndex), "--path="+wimPath)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		detail := strings.ToLower(strings.TrimSpace(stderr.String() + "\n" + stdout.String()))
		for _, marker := range []string{"does not exist", "no matches", "path not found", "no such file"} {
			if strings.Contains(detail, marker) {
				return false, nil
			}
		}
		return false, fmt.Errorf("inspect WIM image %d path %s: %w: %s", imageIndex, wimPath, err, strings.TrimSpace(detail))
	}
	output := strings.ToLower(strings.ReplaceAll(stdout.String(), "\\", "/"))
	return strings.Contains(output, strings.ToLower(wimPath)) || strings.Contains(output, strings.ToLower(filepath.Base(wimPath))), nil
}
''',
)
replace_once(
    "internal/windowsmedia/customizations.go",
    "var inspectCustomizationWIMMetadata = InspectWIMMetadata\n",
    "var inspectCustomizationWIMMetadata = InspectWIMSetupMetadata\n",
    "customization metadata probe",
)
replace_once(
    "internal/windowsmedia/analysis.go",
    "\tmetadata, err := InspectWIMMetadata(ctx, payloadPath)\n",
    "\tmetadata, err := InspectWIMSetupMetadata(ctx, payloadPath)\n",
    "analysis metadata probe",
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tcustomizations := opts.Customizations
\tcustomizations.LoadDrivers = plan.DriverFolder != ""
''',
    '''\tcustomizations := opts.Customizations
\tif customizations.ApplySkuSiPolicy && targetSystem != "uefi" {
\t\treturn errors.New("SkuSiPolicy deployment requires a resolved UEFI Windows target; BIOS/CSM media has no EFI System Partition")
\t}
\tcustomizations.LoadDrivers = plan.DriverFolder != ""
''',
    "writer UEFI guard",
)

# CLI/helper binding.
replace_once(
    "cmd/rufus-linux/main.go",
    '''\twinQualityOfLife := flags.Bool("win-quality-of-life", false, "apply Rufus 4.15 Quality of Life Windows policy")
\twinDisableBitLocker := flags.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption")
''',
    '''\twinQualityOfLife := flags.Bool("win-quality-of-life", false, "apply Rufus 4.15 Quality of Life Windows policy")
\twinApplySkuSiPolicy := flags.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")
\twinDisableBitLocker := flags.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption")
''',
    "CLI flag",
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\tQualityOfLife:        *winQualityOfLife,
\t\tDisableBitLocker:     *winDisableBitLocker,
''',
    '''\t\tQualityOfLife:        *winQualityOfLife,
\t\tApplySkuSiPolicy:     *winApplySkuSiPolicy,
\t\tDisableBitLocker:     *winDisableBitLocker,
''',
    "CLI options binding",
)

# GTK and command builder.
replace_once(
    "gui/rufusarm64.py",
    '''            "quality_of_life": dict(disabled),
            "disable_bitlocker": dict(disabled),
''',
    '''            "quality_of_life": dict(disabled),
            "apply_sku_si_policy": dict(disabled),
            "disable_bitlocker": dict(disabled),
''',
    "unavailable GUI capability",
)
replace_once(
    "gui/rufusarm64.py",
    "    def __init__(self, parent, previous=None, capability_analysis=None):\n",
    "    def __init__(self, parent, previous=None, capability_analysis=None, selected_target_system=DEFAULT_WINDOWS_TARGET_SYSTEM):\n",
    "dialog signature",
)
replace_once(
    "gui/rufusarm64.py",
    '''        self.capabilities = self.capability_analysis.get("capabilities") or {}

        scroll = Gtk.ScrolledWindow()
''',
    '''        self.capabilities = self.capability_analysis.get("capabilities") or {}
        self.selected_target_system = normalize_target_system(selected_target_system or DEFAULT_WINDOWS_TARGET_SYSTEM)
        if self.selected_target_system == "auto":
            self.selected_target_system = str(self.capability_analysis.get("default_target_system") or "").strip().lower()

        scroll = Gtk.ScrolledWindow()
''',
    "dialog target resolution",
)
replace_once(
    "gui/rufusarm64.py",
    '''        self.quality_of_life = self.check(
            box,
            "Apply Rufus Quality of Life changes",
            "Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions.",
            previous.get("quality_of_life", False),
        )
        self.region_locale, self.region_timezone, self.region_iana = current_regional_settings()
''',
    '''        self.quality_of_life = self.check(
            box,
            "Apply Rufus Quality of Life changes",
            "Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions.",
            previous.get("quality_of_life", False),
        )
        self.apply_sku_si_policy = self.check(
            box,
            "Apply the installed Windows SkuSiPolicy on first logon",
            "For qualified Windows 11 UEFI media only. Uses the installed system's own policy and copies it to the EFI System Partition; no host policy file is accepted.",
            previous.get("apply_sku_si_policy", False),
        )
        self.region_locale, self.region_timezone, self.region_iana = current_regional_settings()
''',
    "GUI checkbox",
)
replace_once(
    "gui/rufusarm64.py",
    '''        self.apply_option_capability(self.quality_of_life, "quality_of_life")
        self.apply_option_capability(self.disable_bitlocker, "disable_bitlocker")
''',
    '''        self.apply_option_capability(self.quality_of_life, "quality_of_life")
        sku_allowed = self.apply_option_capability(self.apply_sku_si_policy, "apply_sku_si_policy")
        if sku_allowed and self.selected_target_system != "uefi":
            self.apply_sku_si_policy.set_active(False)
            self.apply_sku_si_policy.set_sensitive(False)
            self.apply_sku_si_policy.set_tooltip_text("SkuSiPolicy deployment requires a UEFI target with an EFI System Partition.")
        self.apply_option_capability(self.disable_bitlocker, "disable_bitlocker")
''',
    "GUI capability and target guard",
)
replace_once(
    "gui/rufusarm64.py",
    '''            "quality_of_life": self.quality_of_life.get_active(),
            "disable_bitlocker": self.disable_bitlocker.get_active(),
''',
    '''            "quality_of_life": self.quality_of_life.get_active(),
            "apply_sku_si_policy": self.apply_sku_si_policy.get_active(),
            "disable_bitlocker": self.disable_bitlocker.get_active(),
''',
    "GUI values",
)
replace_once(
    "gui/rufusarm64.py",
    "        dialog = WindowsOptionsDialog(self, self.windows_options, self.windows_capability_analysis)\n",
    "        dialog = WindowsOptionsDialog(self, self.windows_options, self.windows_capability_analysis, self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM)\n",
    "GUI dialog invocation",
)
replace_once(
    "gui/rufusarm64.py",
    '''                (options.get("quality_of_life"), "Quality of Life app removals and policies"),
                (options.get("disable_bitlocker"), "automatic encryption disabled"),
''',
    '''                (options.get("quality_of_life"), "Quality of Life app removals and policies"),
                (options.get("apply_sku_si_policy"), "installed-system SkuSiPolicy deployment to the EFI System Partition"),
                (options.get("disable_bitlocker"), "automatic encryption disabled"),
''',
    "confirmation summary",
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''    if target_system == "bios" and partition_scheme == "gpt":
        raise ValueError("BIOS/CSM cannot be combined with the GPT partition scheme.")
''',
    '''    if target_system == "bios" and partition_scheme == "gpt":
        raise ValueError("BIOS/CSM cannot be combined with the GPT partition scheme.")
    if options.get("apply_sku_si_policy") and target_system == "bios":
        raise ValueError("SkuSiPolicy deployment requires a UEFI Windows target.")
''',
    "unprivileged target guard",
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''    if options.get("quality_of_life"):
        command.append("--win-quality-of-life")
    if options.get("disable_bitlocker"):
''',
    '''    if options.get("quality_of_life"):
        command.append("--win-quality-of-life")
    if options.get("apply_sku_si_policy"):
        command.append("--win-apply-sku-si-policy")
    if options.get("disable_bitlocker"):
''',
    "GUI command flag",
)

# Tests.
write(
    "internal/windowsconfig/skusi_policy_test.go",
    r'''package windowsconfig

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
''',
)
write(
    "internal/windowsmedia/wimfeatures_test.go",
    r'''//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectWIMPathInEveryImageRequiresEveryEdition(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	script := `#!/bin/sh
if [ "$1" = dir ] && [ "$3" = 1 ]; then
  printf '%s\n' '/Windows/System32/SecureBootUpdates/SkuSiPolicy.p7b'
  exit 0
fi
if [ "$1" = dir ] && [ "$3" = 2 ]; then
  echo 'The path does not exist in the WIM image' >&2
  exit 1
fi
exit 2
`
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	available, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err != nil || !available {
		t.Fatalf("image 1 capability = %v, %v", available, err)
	}
	available, err = inspectWIMPath(context.Background(), tool, "install.wim", 2, skuSiPolicyWIMPath)
	if err != nil || available {
		t.Fatalf("image 2 capability = %v, %v", available, err)
	}
}

func TestInspectWIMPathReportsOperationalFailure(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho 'corrupt WIM' >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err == nil || !strings.Contains(err.Error(), "corrupt wim") {
		t.Fatalf("operational error = %v", err)
	}
}
''',
)
write(
    "gui/test_windows_skusi_policy.py",
    r'''import tempfile
from pathlib import Path
import unittest

from rufusarm64_logic import build_writer_command


class WindowsSkuSiPolicyCommandTests(unittest.TestCase):
    def base(self, target_system="uefi", options=None):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "windows.iso"
            image.write_bytes(b"identity-bound-windows-image")
            return build_writer_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-helper",
                str(image),
                "/dev/sdz",
                "target-token",
                False,
                str(Path(directory) / "cancel"),
                windows_options=options or {},
                partition_scheme="gpt" if target_system == "uefi" else "mbr",
                target_system=target_system,
                filesystem="fat32",
            )

    def test_binds_policy_flag_for_uefi(self):
        command = self.base(options={"apply_sku_si_policy": True})
        self.assertIn("--win-apply-sku-si-policy", command)

    def test_rejects_policy_for_bios(self):
        with self.assertRaisesRegex(ValueError, "requires a UEFI"):
            self.base(target_system="bios", options={"apply_sku_si_policy": True})


if __name__ == "__main__":
    unittest.main()
''',
)

# User-facing record.
replace_once(
    "CHANGELOG.md",
    "## Unreleased\n\n",
    "## Unreleased\n\n- Added capability-gated Windows 11 SkuSiPolicy deployment for qualified UEFI installation media, using only the installed system's own policy and refusing BIOS/CSM, missing-policy, split-SWM, server, Windows 10, and unknown-media requests.\n",
    "changelog heading",
)
