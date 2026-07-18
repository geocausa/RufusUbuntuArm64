from pathlib import Path


def replace_exact(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_exact(
    "gui/rufusarm64_persistence_logic.py",
    '''def build_create_command(\n    pkexec,\n    persistence_helper,\n    image,\n    source_identity,\n    device,\n    target_identity,\n    persistence_gib,\n    volume_label,\n    cancel_path,\n):\n''',
    '''def build_create_command(\n    pkexec,\n    persistence_helper,\n    image,\n    source_identity,\n    device,\n    target_identity,\n    persistence_gib,\n    volume_label,\n    cancel_path,\n    runtime_uefi_validation=False,\n):\n''',
)
replace_exact(
    "gui/rufusarm64_persistence_logic.py",
    '''    persistence_gib = normalize_persistence_gib(persistence_gib)\n    label = normalize_boot_label(volume_label)\n    return [\n        values[0], values[1],\n        "--image", values[2],\n        "--expected-source-identity", values[3],\n        "--device", values[4],\n        "--expected-identity", values[5],\n        "--persistence-size", f"{persistence_gib}G" if persistence_gib else "0",\n        "--volume-label", label,\n        "--cancel-file", values[6],\n        "--json-progress",\n        "--yes",\n    ]\n''',
    '''    persistence_gib = normalize_persistence_gib(persistence_gib)\n    label = normalize_boot_label(volume_label)\n    if not isinstance(runtime_uefi_validation, bool):\n        raise ValueError("Runtime UEFI media validation must be an explicit boolean selection.")\n    command = [\n        values[0], values[1],\n        "--image", values[2],\n        "--expected-source-identity", values[3],\n        "--device", values[4],\n        "--expected-identity", values[5],\n        "--persistence-size", f"{persistence_gib}G" if persistence_gib else "0",\n        "--volume-label", label,\n        "--cancel-file", values[6],\n        "--json-progress",\n        "--yes",\n    ]\n    if runtime_uefi_validation:\n        command.append("--runtime-uefi-validation")\n    return command\n''',
)

replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.last_status = None\n        self.connect("delete-event", self.on_delete)\n''',
    '''        self.last_status = None\n        self.runtime_validation_requested = False\n        self.connect("delete-event", self.on_delete)\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.volume_label.connect("changed", self.selection_changed)\n        grid.attach(self.volume_label, 1, 3, 2, 1)\n\n        frame = Gtk.Frame(label="Mandatory compatibility analysis")\n''',
    '''        self.volume_label.connect("changed", self.selection_changed)\n        grid.attach(self.volume_label, 1, 3, 2, 1)\n\n        self._label(grid, "Boot-time validation", 4)\n        runtime_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)\n        self.runtime_uefi_validation = Gtk.CheckButton(label="Validate media at UEFI boot")\n        self.runtime_uefi_validation.set_active(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        self.runtime_uefi_validation.connect("toggled", self.selection_changed)\n        runtime_box.pack_start(self.runtime_uefi_validation, False, False, 0)\n        runtime_warning = Gtk.Label(label=(\n            "Unsigned development loader — Secure Boot compatibility is not established"\n        ))\n        runtime_warning.set_xalign(0)\n        runtime_warning.set_line_wrap(True)\n        runtime_box.pack_start(runtime_warning, False, False, 0)\n        grid.attach(runtime_box, 1, 4, 2, 1)\n\n        frame = Gtk.Frame(label="Mandatory compatibility analysis")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''            self.plan = self.plan_key = None\n            self.create_button.set_sensitive(False)\n            self.summary.set_text("Selection changed. Run compatibility analysis again before creation.")\n''',
    '''            self.plan = self.plan_key = None\n            self.create_button.set_sensitive(False)\n            self.runtime_uefi_validation.set_sensitive(False)\n            self.summary.set_text("Selection changed. Run compatibility analysis again before creation.")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        label = normalize_boot_label(self.volume_label.get_text())\n        key = (image, source_identity, target_identity, target_size, size_gib)\n        return image, source_identity, device, target_identity, target_size, size_gib, label, key\n''',
    '''        label = normalize_boot_label(self.volume_label.get_text())\n        runtime_validation = bool(self.runtime_uefi_validation.get_active())\n        key = (image, source_identity, target_identity, target_size, size_gib, label, runtime_validation)\n        return image, source_identity, device, target_identity, target_size, size_gib, label, runtime_validation, key\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        self.progress.set_text("Scanning removable drives…")\n''',
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        self.progress.set_text("Scanning removable drives…")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        for widget in (self.image, self.target, self.size, self.volume_label):\n            widget.set_sensitive(not busy)\n        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)\n''',
    '''        for widget in (self.image, self.target, self.size, self.volume_label):\n            widget.set_sensitive(not busy)\n        self.runtime_uefi_validation.set_sensitive(\n            not busy and not self.device_refreshing and self.plan is not None and self.plan_key is not None\n        )\n        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''            image, source_id, _device, _target_id, target_size, size_gib, _label, key = self.selection()\n''',
    '''            image, source_id, _device, _target_id, target_size, size_gib, _label, _runtime_validation, key = self.selection()\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''                self.create_button.set_sensitive(True)\n                self.progress.set_fraction(1)\n''',
    '''                self.create_button.set_sensitive(True)\n                self.runtime_uefi_validation.set_sensitive(True)\n                self.progress.set_fraction(1)\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        if cancelled:\n''',
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        if cancelled:\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''            image, source_id, device, target_id, target_size, size_gib, label, key = self.selection()\n            if key != self.plan_key:\n                raise ValueError("The image, USB, or requested size changed. Analyze again.")\n''',
    '''            image, source_id, device, target_id, target_size, size_gib, label, runtime_validation, key = self.selection()\n            if key != self.plan_key:\n                raise ValueError("The image, USB, boot label, validation option, or requested size changed. Analyze again.")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''                size_gib, label, cancel_path,\n            )\n''',
    '''                size_gib, label, cancel_path, runtime_validation,\n            )\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        dialog.format_secondary_text(\n            f"ALL DATA on {device.get('path')} ({human_bytes(target_size)}) will be permanently erased.\\n\\n"\n            f"{plan_summary(self.plan, human_bytes)}\\n\\n"\n            "This is a persistent live system, not a conventional installed OS. Software checks cannot guarantee firmware boot. "\n            "After creation, boot this exact USB and complete start/reboot/verify qualification."\n        )\n''',
    '''        runtime_confirmation = ""\n        if runtime_validation:\n            runtime_confirmation = (\n                "\\n\\nBoot-time UEFI media validation will replace EFI/BOOT/BOOTAA64.EFI and preserve the "\n                "original as EFI/BOOT/bootaa64_original.efi. Unsigned development loader — "\n                "Secure Boot compatibility is not established."\n            )\n        dialog.format_secondary_text(\n            f"ALL DATA on {device.get('path')} ({human_bytes(target_size)}) will be permanently erased.\\n\\n"\n            f"{plan_summary(self.plan, human_bytes)}"\n            f"{runtime_confirmation}\\n\\n"\n            "This is a persistent live system, not a conventional installed OS. Software checks cannot guarantee firmware boot. "\n            "After creation, boot this exact USB and complete start/reboot/verify qualification."\n        )\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.last_status = None\n        self.log.get_buffer().set_text("")\n''',
    '''        self.last_status = None\n        self.runtime_validation_requested = runtime_validation\n        self.log.get_buffer().set_text("")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.append_log(plan_summary(self.plan, human_bytes))\n        self.set_busy(True, "create")\n''',
    '''        self.append_log(plan_summary(self.plan, human_bytes))\n        if runtime_validation:\n            self.append_log(\n                "Boot-time UEFI validation requested: package-owned unsigned loader; original fallback will be preserved."\n            )\n        self.set_busy(True, "create")\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        if code == 0:\n''',
    '''        self.plan = self.plan_key = None\n        self.create_button.set_sensitive(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        runtime_validation = self.runtime_validation_requested\n        self.runtime_validation_requested = False\n        if code == 0:\n''',
)
replace_exact(
    "gui/rufusarm64_persistence.py",
    '''            self.detail.set_text("Internal checks passed. Boot the USB, then qualify persistence across one reboot.")\n            self.message(\n                "Persistent live media was created and checked.\\n\\nBoot it and run:\\n\\n"\n                "sudo rufusarm64-cli qualify start --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-initial.json\\n\\n"\n                "Reboot the same USB, then run qualify verify with a new output file. Until that passes, treat this image/hardware combination as unqualified.",\n                Gtk.MessageType.INFO,\n            )\n''',
    '''            if runtime_validation:\n                self.detail.set_text(\n                    "Internal checks and the boot-time media manifest passed. Physical boot and reboot qualification are still required."\n                )\n                runtime_note = (\n                    "\\n\\nBoot-time UEFI media validation is installed. The validator is unsigned, so Secure Boot "\n                    "compatibility is not established. Physical boot and reboot qualification remain required."\n                )\n            else:\n                self.detail.set_text("Internal checks passed. Boot the USB, then qualify persistence across one reboot.")\n                runtime_note = ""\n            self.message(\n                "Persistent live media was created and checked."\n                f"{runtime_note}\\n\\nBoot it and run:\\n\\n"\n                "sudo rufusarm64-cli qualify start --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-initial.json\\n\\n"\n                "Reboot the same USB, then run qualify verify with a new output file. Until that passes, treat this image/hardware combination as unqualified.",\n                Gtk.MessageType.INFO,\n            )\n''',
)

logic_tests = r'''import unittest

from rufusarm64_persistence_logic import build_create_command


class RuntimeIntegrityPersistenceLogicTests(unittest.TestCase):
    def base_command(self, enabled=False):
        return build_create_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
            "/images/ubuntu.iso",
            "1:2:3:4:5",
            "/dev/sda",
            "target-identity",
            16,
            "RUFUS-LIVE",
            "/run/user/1000/rufusarm64.cancel",
            enabled,
        )

    def test_runtime_validation_appends_only_fixed_boolean_flag(self):
        disabled = self.base_command(False)
        enabled = self.base_command(True)
        self.assertNotIn("--runtime-uefi-validation", disabled)
        self.assertEqual(enabled.count("--runtime-uefi-validation"), 1)
        self.assertNotIn("--runtime-uefi-loader", enabled)
        self.assertNotIn("--runtime-uefi-loader-sha256", enabled)
        self.assertEqual(enabled[:-1], disabled)

    def test_runtime_validation_requires_explicit_boolean(self):
        for value in (1, "true", None, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "explicit boolean"):
                    self.base_command(value)


class RuntimeIntegrityGUISourceTests(unittest.TestCase):
    def test_guarded_unsigned_wording_and_no_asset_picker(self):
        with open("gui/rufusarm64_persistence.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("Validate media at UEFI boot", source)
        self.assertIn("Unsigned development loader — Secure Boot compatibility is not established", source)
        self.assertIn("EFI/BOOT/bootaa64_original.efi", source)
        self.assertIn("self.runtime_uefi_validation.set_sensitive(False)", source)
        self.assertIn("self.runtime_uefi_validation.set_sensitive(True)", source)
        self.assertIn("runtime_validation_requested", source)
        self.assertNotIn("Gtk.FileChooserButton(title=\"Choose an EFI", source)
        self.assertNotIn("runtime_uefi_loader_path", source)
        self.assertNotIn("runtime_uefi_loader_sha256", source)


if __name__ == "__main__":
    unittest.main()
'''
Path("gui/test_persistence_runtime_integrity.py").write_text(logic_tests, encoding="utf-8")
