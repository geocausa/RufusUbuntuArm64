#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"missing anchor: {label}")
    return text.replace(old, new, 1)


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


# Close the final pre-erasure staging gap and make readback parent traversal no-follow.
path = Path("internal/windowsmedia/ca2023.go")
text = path.read_text(encoding="utf-8")
text = text.replace(
    "WindowsCA2023Signed bool",
    "WindowsCA2023CertificateEvidence bool",
)
text = text.replace(
    "bootmgfwEvidence.WindowsCA2023Signed || !bootmgrEvidence.WindowsCA2023Signed",
    "bootmgfwEvidence.WindowsCA2023CertificateEvidence || !bootmgrEvidence.WindowsCA2023CertificateEvidence",
)
text = text.replace(
    "staged _EX bootloaders are not both signed through Windows UEFI CA 2023",
    "staged _EX bootloaders do not both carry embedded certificate-chain evidence identifying Windows UEFI CA 2023",
)
text = text.replace(
    "WindowsCA2023Signed: ca2023",
    "WindowsCA2023CertificateEvidence: ca2023",
)
aggregate = '''
func verifyWindowsCA2023Staging(plan *WindowsCA2023Plan) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		if err := verifyStagedWindowsCA2023Asset(asset); err != nil {
			return err
		}
	}
	return nil
}

'''
marker = "func verifyStagedWindowsCA2023Asset(asset WindowsCA2023Asset) error {\n"
if aggregate.strip() not in text:
    if marker not in text:
        raise SystemExit("missing anchor: aggregate staging verifier")
    text = text.replace(marker, aggregate + marker, 1)
old_verify = '''func verifyWindowsCA2023(root string, plan *WindowsCA2023Plan) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		destination := filepath.Join(root, filepath.FromSlash(asset.Destination))
		info, err := os.Lstat(destination)
		if err != nil {
			return fmt.Errorf("stat CA 2023 replacement %s: %w", asset.Destination, err)
		}
		if !info.Mode().IsRegular() || uint64(info.Size()) != asset.Size {
			return fmt.Errorf("CA 2023 replacement %s has unexpected type or size", asset.Destination)
		}
		digest, err := fileSHA256(destination)
'''
new_verify = '''func verifyWindowsCA2023(root string, plan *WindowsCA2023Plan) error {
	if plan == nil {
		return nil
	}
	for _, asset := range plan.Assets {
		destination, err := existingCA2023Destination(root, asset.Destination)
		if err != nil {
			return err
		}
		info, err := os.Lstat(destination)
		if err != nil {
			return fmt.Errorf("stat CA 2023 replacement %s: %w", asset.Destination, err)
		}
		if !info.Mode().IsRegular() || uint64(info.Size()) != asset.Size {
			return fmt.Errorf("CA 2023 replacement %s has unexpected type or size", asset.Destination)
		}
		digest, err := fileSHA256(destination)
'''
text = replace_once(text, old_verify, new_verify, "no-follow CA 2023 readback")
existing_helper = '''
func existingCA2023Destination(root, relative string) (string, error) {
	clean, err := cleanCA2023Destination(relative)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("CA 2023 readback root is not a real directory")
	}
	current := root
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", fmt.Errorf("stat CA 2023 readback parent %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("CA 2023 readback parent is not a real directory: %s", current)
		}
	}
	return filepath.Join(root, clean), nil
}

'''
marker = "func verifyWindowsCA2023(root string, plan *WindowsCA2023Plan) error {\n"
if existing_helper.strip() not in text:
    if marker not in text:
        raise SystemExit("missing anchor: existing CA 2023 destination helper")
    text = text.replace(marker, existing_helper + marker, 1)
write(str(path), text)

path = Path("internal/windowsmedia/windowsmedia.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\tif opts.BeforeDestructive != nil {\n\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\treturn fmt.Errorf("target safety check: %w", err)\n\t\t}\n\t}\n\ttargetChanged = true\n''',
    '''\tif opts.BeforeDestructive != nil {\n\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\treturn fmt.Errorf("target safety check: %w", err)\n\t\t}\n\t}\n\tif err := verifyWindowsCA2023Staging(plan.CA2023); err != nil {\n\t\treturn fmt.Errorf("revalidate staged Windows UEFI CA 2023 assets immediately before erasing the USB: %w", err)\n\t}\n\ttargetChanged = true\n''',
    "final pre-erasure CA 2023 staging verification",
)
text = text.replace(
    "Qualified %d Windows UEFI CA 2023 replacement files",
    "Qualified %d Windows UEFI CA 2023 replacement files with embedded CA 2023 certificate-chain evidence",
)
write(str(path), text)

path = Path("internal/windowsmedia/ca2023_integration_test.go")
text = path.read_text(encoding="utf-8")
extra_tests = r'''
func TestVerifyWindowsCA2023StagingRejectsChangedAssetBeforeErase(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "bootmgfw_EX.efi")
	if err := os.WriteFile(staged, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(staged)
	if err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: "EFI/BOOT/BOOTAA64.EFI",
		Size:        5,
		SHA256:      fmtDigest(digest),
		sourcePath:  staged,
	}}}
	if err := os.WriteFile(staged, []byte("later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsCA2023Staging(plan); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected final pre-erasure staging refusal, got %v", err)
	}
}

func TestVerifyWindowsCA2023RejectsSymlinkedReadbackParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "EFI"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "EFI", "BOOT")); err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: "EFI/BOOT/BOOTAA64.EFI",
		Size:        1,
		SHA256:      strings.Repeat("0", 64),
	}}}
	if err := verifyWindowsCA2023(root, plan); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("expected symlinked readback-parent refusal, got %v", err)
	}
}
'''
if "TestVerifyWindowsCA2023StagingRejectsChangedAssetBeforeErase" not in text:
    text = text.rstrip() + "\n\n" + extra_tests
write(str(path), text)


# Pure command builder: require the same analyzed capability and resolved layout evidence.
path = Path("gui/rufusarm64_logic.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    quick_format=DEFAULT_QUICK_FORMAT,\n    bad_block_check=DEFAULT_BAD_BLOCK_CHECK,\n):\n''',
    '''    quick_format=DEFAULT_QUICK_FORMAT,\n    bad_block_check=DEFAULT_BAD_BLOCK_CHECK,\n    windows_capability_analysis=None,\n):\n''',
    "writer command capability-analysis argument",
)
text = replace_once(
    text,
    '''    options = dict(windows_options or {})\n    partition_scheme = normalize_partition_scheme(partition_scheme)\n    target_system = normalize_target_system(target_system)\n    if target_system == "bios" and partition_scheme == "gpt":\n''',
    '''    options = dict(windows_options or {})\n    analysis = dict(windows_capability_analysis or {})\n    partition_scheme = normalize_partition_scheme(partition_scheme)\n    target_system = normalize_target_system(target_system)\n    filesystem = normalize_filesystem(filesystem)\n    resolved_target_system = target_system\n    resolved_filesystem = filesystem\n    if resolved_target_system == "auto":\n        resolved_target_system = str(analysis.get("default_target_system") or "").strip().lower()\n    if resolved_filesystem == "auto":\n        resolved_filesystem = str(analysis.get("default_filesystem") or "").strip().lower()\n    if target_system == "bios" and partition_scheme == "gpt":\n''',
    "writer command resolved layout evidence",
)
text = replace_once(
    text,
    '''    if options.get("apply_sku_si_policy") and target_system == "bios":\n        raise ValueError("SkuSiPolicy deployment requires a UEFI Windows target.")\n    command = [\n''',
    '''    if options.get("apply_sku_si_policy") and resolved_target_system != "uefi":\n        raise ValueError("SkuSiPolicy deployment requires a UEFI Windows target.")\n    if options.get("use_windows_ca_2023_bootloaders"):\n        capability = analysis.get("windows_ca_2023")\n        if not isinstance(capability, dict) or not capability.get("available"):\n            reason = capability.get("reason") if isinstance(capability, dict) else ""\n            raise ValueError(str(reason or "Windows UEFI CA 2023 bootloaders were not proven by the read-only media analysis."))\n        if resolved_target_system != "uefi":\n            raise ValueError("Windows UEFI CA 2023 bootloader replacement requires a UEFI target.")\n        if resolved_filesystem != "fat32":\n            raise ValueError("Windows UEFI CA 2023 bootloader replacement currently requires FAT32; NTFS uses a CA 2011-signed UEFI:NTFS first stage.")\n    command = [\n''',
    "writer command CA 2023 guard",
)
text = text.replace(
    '        normalize_volume_label(volume_label, filesystem),',
    '        normalize_volume_label(volume_label, filesystem),',
)
text = text.replace(
    '        normalize_filesystem(filesystem),',
    '        filesystem,',
    1,
)
text = replace_once(
    text,
    '''    if options.get("apply_sku_si_policy"):\n        command.append("--win-apply-sku-si-policy")\n    if options.get("disable_bitlocker"):\n''',
    '''    if options.get("apply_sku_si_policy"):\n        command.append("--win-apply-sku-si-policy")\n    if options.get("use_windows_ca_2023_bootloaders"):\n        command.append("--win-use-ca-2023-bootloaders")\n    if options.get("disable_bitlocker"):\n''',
    "writer command CA 2023 flag",
)
write(str(path), text)


# GTK analysis normalization, option, layout gating, confirmation, and evidence display.
path = Path("gui/rufusarm64.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    default_scheme = str(payload.get("default_partition_scheme") or "").strip().lower()\n    default_target = str(payload.get("default_target_system") or "").strip().lower()\n    if default_scheme not in {"gpt", "mbr"} or default_target not in {"uefi", "bios"}:\n        raise ValueError("Windows capability analysis is missing a resolved automatic layout.")\n    normalized = dict(payload)\n''',
    '''    default_scheme = str(payload.get("default_partition_scheme") or "").strip().lower()\n    default_target = str(payload.get("default_target_system") or "").strip().lower()\n    default_filesystem = str(payload.get("default_filesystem") or "").strip().lower()\n    if default_scheme not in {"gpt", "mbr"} or default_target not in {"uefi", "bios"}:\n        raise ValueError("Windows capability analysis is missing a resolved automatic layout.")\n    if default_filesystem not in {"fat32", "ntfs"}:\n        raise ValueError("Windows capability analysis is missing a resolved automatic filesystem.")\n    ca2023 = payload.get("windows_ca_2023")\n    if not isinstance(ca2023, dict) or not isinstance(ca2023.get("available"), bool):\n        raise ValueError("Windows capability analysis is missing CA 2023 bootloader evidence.")\n    ca2023 = dict(ca2023)\n    ca2023["reason"] = str(ca2023.get("reason") or "")\n    if ca2023["available"]:\n        if int(ca2023.get("image_index") or 0) not in {1, 2}:\n            raise ValueError("Windows CA 2023 evidence has an invalid boot.wim image index.")\n        if str(ca2023.get("architecture") or "").strip().lower() not in {"arm64", "amd64", "x86"}:\n            raise ValueError("Windows CA 2023 evidence has an invalid architecture.")\n        if int(ca2023.get("asset_count") or 0) < 3:\n            raise ValueError("Windows CA 2023 evidence has an invalid replacement-file count.")\n        manifest = str(ca2023.get("manifest_sha256") or "").strip().lower()\n        if not re.fullmatch(r"[0-9a-f]{64}", manifest):\n            raise ValueError("Windows CA 2023 evidence has an invalid manifest SHA-256.")\n        ca2023["manifest_sha256"] = manifest\n    normalized = dict(payload)\n''',
    "normalize CA 2023 capability analysis",
)
text = replace_once(
    text,
    '''    normalized["default_partition_scheme"] = default_scheme\n    normalized["default_target_system"] = default_target\n    return normalized\n''',
    '''    normalized["default_partition_scheme"] = default_scheme\n    normalized["default_target_system"] = default_target\n    normalized["default_filesystem"] = default_filesystem\n    normalized["windows_ca_2023"] = ca2023\n    return normalized\n''',
    "normalized CA 2023 evidence assignment",
)
text = replace_once(
    text,
    '''        "default_partition_scheme": "",\n        "default_target_system": "",\n        "capabilities": {\n''',
    '''        "default_partition_scheme": "",\n        "default_target_system": "",\n        "default_filesystem": "",\n        "windows_ca_2023": {"available": False, "reason": reason},\n        "capabilities": {\n''',
    "unavailable analysis CA 2023 evidence",
)
text = replace_once(
    text,
    '''            "apply_sku_si_policy": dict(disabled),\n            "disable_bitlocker": dict(disabled),\n''',
    '''            "apply_sku_si_policy": dict(disabled),\n            "use_windows_ca_2023_bootloaders": dict(disabled),\n            "disable_bitlocker": dict(disabled),\n''',
    "unavailable CA 2023 option capability",
)
text = replace_once(
    text,
    '''    def __init__(self, parent, previous=None, capability_analysis=None, selected_target_system=DEFAULT_WINDOWS_TARGET_SYSTEM):\n''',
    '''    def __init__(self, parent, previous=None, capability_analysis=None, selected_target_system=DEFAULT_WINDOWS_TARGET_SYSTEM, selected_filesystem=DEFAULT_WINDOWS_FILESYSTEM):\n''',
    "Windows options selected filesystem argument",
)
text = replace_once(
    text,
    '''        if self.selected_target_system == "auto":\n            self.selected_target_system = str(self.capability_analysis.get("default_target_system") or "").strip().lower()\n\n        scroll = Gtk.ScrolledWindow()\n''',
    '''        if self.selected_target_system == "auto":\n            self.selected_target_system = str(self.capability_analysis.get("default_target_system") or "").strip().lower()\n        self.selected_filesystem = normalize_filesystem(selected_filesystem or DEFAULT_WINDOWS_FILESYSTEM)\n        if self.selected_filesystem == "auto":\n            self.selected_filesystem = str(self.capability_analysis.get("default_filesystem") or "").strip().lower()\n\n        scroll = Gtk.ScrolledWindow()\n''',
    "resolve selected filesystem in dialog",
)
text = replace_once(
    text,
    '''                "Every option below is optional. RufusArm64 creates an autounattend.xml file on the USB; "\n                "the Windows ISO itself is not changed. Leave everything unchecked for standard Microsoft setup."\n''',
    '''                "Every option below is optional. Most setup choices create an autounattend.xml file. "\n                "The CA 2023 option instead replaces a bounded set of boot files on the completed USB from the selected ISO's own boot.wim. "\n                "The Windows ISO itself is never modified. Leave everything unchecked for standard Microsoft setup."\n''',
    "accurate Windows options introduction",
)
text = replace_once(
    text,
    '''        self.apply_sku_si_policy = self.check(\n            box,\n            "Apply the installed Windows SkuSiPolicy on first logon",\n            "For qualified Windows 11 UEFI media only. Uses the installed system's own policy and copies it to the EFI System Partition; no host policy file is accepted.",\n            previous.get("apply_sku_si_policy", False),\n        )\n        self.region_locale, self.region_timezone, self.region_iana = current_regional_settings()\n''',
    '''        self.apply_sku_si_policy = self.check(\n            box,\n            "Apply the installed Windows SkuSiPolicy on first logon",\n            "For qualified Windows 11 UEFI media only. Uses the installed system's own policy and copies it to the EFI System Partition; no host policy file is accepted.",\n            previous.get("apply_sku_si_policy", False),\n        )\n        self.use_ca_2023_bootloaders = self.check(\n            box,\n            "Use Windows UEFI CA 2023 bootloaders from this ISO",\n            "Available only when read-only analysis proves a complete architecture-matched _EX set in Windows 11 client boot.wim and the resolved layout is UEFI/FAT32. The target computer's firmware must trust Windows UEFI CA 2023.",\n            previous.get("use_windows_ca_2023_bootloaders", False),\n        )\n        self.region_locale, self.region_timezone, self.region_iana = current_regional_settings()\n''',
    "CA 2023 GTK checkbox",
)
text = replace_once(
    text,
    '''        sku_allowed = self.apply_option_capability(self.apply_sku_si_policy, "apply_sku_si_policy")\n        if sku_allowed and self.selected_target_system != "uefi":\n            self.apply_sku_si_policy.set_active(False)\n            self.apply_sku_si_policy.set_sensitive(False)\n            self.apply_sku_si_policy.set_tooltip_text("SkuSiPolicy deployment requires a UEFI target with an EFI System Partition.")\n        self.apply_option_capability(self.disable_bitlocker, "disable_bitlocker")\n''',
    '''        sku_allowed = self.apply_option_capability(self.apply_sku_si_policy, "apply_sku_si_policy")\n        if sku_allowed and self.selected_target_system != "uefi":\n            self.apply_sku_si_policy.set_active(False)\n            self.apply_sku_si_policy.set_sensitive(False)\n            self.apply_sku_si_policy.set_tooltip_text("SkuSiPolicy deployment requires a UEFI target with an EFI System Partition.")\n        ca_allowed = self.apply_option_capability(self.use_ca_2023_bootloaders, "use_windows_ca_2023_bootloaders")\n        if ca_allowed and self.selected_target_system != "uefi":\n            self.use_ca_2023_bootloaders.set_active(False)\n            self.use_ca_2023_bootloaders.set_sensitive(False)\n            self.use_ca_2023_bootloaders.set_tooltip_text("Windows UEFI CA 2023 bootloader replacement requires a resolved UEFI target.")\n        elif ca_allowed and self.selected_filesystem != "fat32":\n            self.use_ca_2023_bootloaders.set_active(False)\n            self.use_ca_2023_bootloaders.set_sensitive(False)\n            self.use_ca_2023_bootloaders.set_tooltip_text("Windows UEFI CA 2023 bootloader replacement currently requires FAT32; NTFS uses the pinned CA 2011-signed UEFI:NTFS first stage.")\n        self.apply_option_capability(self.disable_bitlocker, "disable_bitlocker")\n''',
    "CA 2023 GTK layout gating",
)
text = replace_once(
    text,
    '''            "apply_sku_si_policy": self.apply_sku_si_policy.get_active(),\n            "disable_bitlocker": self.disable_bitlocker.get_active(),\n''',
    '''            "apply_sku_si_policy": self.apply_sku_si_policy.get_active(),\n            "use_windows_ca_2023_bootloaders": self.use_ca_2023_bootloaders.get_active(),\n            "disable_bitlocker": self.disable_bitlocker.get_active(),\n''',
    "CA 2023 GTK value",
)
text = replace_once(
    text,
    '''        dialog = WindowsOptionsDialog(self, self.windows_options, self.windows_capability_analysis, self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM)\n''',
    '''        dialog = WindowsOptionsDialog(\n            self,\n            self.windows_options,\n            self.windows_capability_analysis,\n            self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM,\n            self.filesystem_combo.get_active_id() or DEFAULT_WINDOWS_FILESYSTEM,\n        )\n''',
    "pass filesystem to Windows options dialog",
)
text = replace_once(
    text,
    '''                (options.get("apply_sku_si_policy"), "installed-system SkuSiPolicy deployment to the EFI System Partition"),\n                (options.get("disable_bitlocker"), "automatic encryption disabled"),\n''',
    '''                (options.get("apply_sku_si_policy"), "installed-system SkuSiPolicy deployment to the EFI System Partition"),\n                (options.get("use_windows_ca_2023_bootloaders"), "Windows UEFI CA 2023 boot-file replacement with mandatory SHA-256 readback; firmware CA 2023 trust required"),\n                (options.get("disable_bitlocker"), "automatic encryption disabled"),\n''',
    "CA 2023 destructive confirmation summary",
)
text = replace_once(
    text,
    '''                    bad_block_check,\n                )\n''',
    '''                    bad_block_check,\n                    windows_capability_analysis=self.windows_capability_analysis,\n                )\n''',
    "pass analysis to writer command",
)
text = replace_once(
    text,
    '''        rate = float(event.get("rate") or 0)\n        stage_key = event.get("stage") or "working"\n''',
    '''        rate = float(event.get("rate") or 0)\n        digest = str(event.get("sha256") or "").strip().lower()\n        stage_key = event.get("stage") or "working"\n''',
    "event evidence digest",
)
text = replace_once(
    text,
    '''        elif message and status_key != self.last_status_key:\n            self.append_log(message)\n            self.last_status_key = status_key\n\n        if total > 0:\n''',
    '''        elif message and status_key != self.last_status_key:\n            self.append_log(message)\n            self.last_status_key = status_key\n        if digest and stage_key in {"windows_ca_2023", "verify_ca_2023"} and digest != getattr(self, "last_ca2023_manifest", ""):\n            self.append_log("Windows UEFI CA 2023 replacement manifest SHA-256: " + digest)\n            self.last_ca2023_manifest = digest\n\n        if total > 0:\n''',
    "GUI CA 2023 manifest evidence",
)
write(str(path), text)


# Pure GUI command and structural regression coverage.
write("gui/test_windows_ca2023.py", r'''import tempfile
from pathlib import Path
import unittest

from rufusarm64_logic import build_writer_command


class WindowsCA2023CommandTests(unittest.TestCase):
    def analysis(self, default_target="uefi", default_filesystem="fat32", available=True, reason=""):
        return {
            "default_target_system": default_target,
            "default_filesystem": default_filesystem,
            "windows_ca_2023": {
                "available": available,
                "reason": reason,
                "image_index": 2,
                "architecture": "arm64",
                "asset_count": 14,
                "manifest_sha256": "a" * 64,
            },
        }

    def base(self, target_system="uefi", filesystem="fat32", analysis=None, enabled=True):
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
                windows_options={"use_windows_ca_2023_bootloaders": enabled},
                partition_scheme="gpt",
                target_system=target_system,
                filesystem=filesystem,
                windows_capability_analysis=analysis or self.analysis(),
            )

    def test_binds_flag_for_explicit_uefi_fat32(self):
        self.assertIn("--win-use-ca-2023-bootloaders", self.base())

    def test_binds_flag_when_automatic_resolves_to_uefi_fat32(self):
        command = self.base(target_system="auto", filesystem="auto")
        self.assertIn("--win-use-ca-2023-bootloaders", command)
        self.assertIn("auto", command)

    def test_rejects_unproven_media(self):
        with self.assertRaisesRegex(ValueError, "incomplete _EX set"):
            self.base(analysis=self.analysis(available=False, reason="incomplete _EX set"))

    def test_rejects_bios_resolution(self):
        with self.assertRaisesRegex(ValueError, "requires a UEFI"):
            self.base(target_system="auto", analysis=self.analysis(default_target="bios"))

    def test_rejects_ntfs_resolution(self):
        with self.assertRaisesRegex(ValueError, "requires FAT32"):
            self.base(filesystem="auto", analysis=self.analysis(default_filesystem="ntfs"))


if __name__ == "__main__":
    unittest.main()
''')

path = Path("gui/test_source_structure.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''        for fragment in ("apply_option_capability", "bypass_hardware_checks", "bypass_online_account", "local_account"):\n''',
    '''        for fragment in ("apply_option_capability", "bypass_hardware_checks", "bypass_online_account", "local_account", "use_windows_ca_2023_bootloaders", "selected_filesystem"):\n''',
    "source structure CA 2023 gating",
)
write(str(path), text)
