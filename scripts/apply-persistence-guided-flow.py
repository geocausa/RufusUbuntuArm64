#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]


def replace_once(path, old, new):
    target = root / path
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    target.write_text(text.replace(old, new, 1))


logic = root / "gui/rufusarm64_persistence_logic.py"
text = logic.read_text()
text = text.replace("def plan_summary(plan, human_bytes):\n", "def technical_plan_summary(plan, human_bytes):\n", 1)
text += '''\n\ndef user_plan_summary(plan, human_bytes):\n    return "\\n".join([\n        f"Supported live system: {plan['name']}",\n        f"Space for saved files and settings: {human_bytes(plan['size'])}",\n        "RufusArm64 will prepare the USB so supported changes can survive a reboot.",\n    ])\n\n\ndef completion_checklist():\n    return "\\n".join([\n        "1. Restart the computer and boot from the new USB.",\n        "2. In the live system, create a small test file in your Home folder.",\n        "3. Restart and boot from the same USB again.",\n        "4. Confirm that the test file is still present.",\n    ])\n'''
logic.write_text(text)

replace_once(
    "gui/rufusarm64_persistence.py",
    "    normalize_plan,\n    plan_summary,\n)",
    "    normalize_plan,\n    technical_plan_summary,\n    user_plan_summary,\n    completion_checklist,\n)",
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.set_default_size(760, 700)\n',
    '        self.set_default_size(760, 680)\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '            "The live system is copied to a writable FAT32 boot partition. A separate ext4 partition stores "\n            "supported file, setting, and package changes across reboots. This remains a live environment, not a normal installation."\n',
    '            "Choose a supported Ubuntu or Debian ISO, select a removable USB drive, and choose how much space "\n            "to keep for files and settings. RufusArm64 checks compatibility before it allows the USB to be erased."\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '            "Experimental hardware scope: Ubuntu 20.04+ casper or Debian live-boot, GPT/UEFI, FAT32-safe files, "\n            "and a matching fallback EFI loader. A real boot and reboot qualification is still required."\n',
    '            "This feature supports recognized Ubuntu 20.04 or newer and Debian live images. Some images or computers "\n            "may not be compatible; RufusArm64 checks the ISO before writing anything to the USB."\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self._label(grid, "Persistent storage", 2)\n',
    '        self._label(grid, "Space for saved changes", 2)\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.size.set_value(16)\n',
    '        self.size.set_value(0)\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        size_row.pack_start(Gtk.Label(label="GiB (0 = suitable remaining space)"), False, False, 0)\n',
    '        size_help = Gtk.Label(label="GiB — leave at 0 to use the recommended available space")\n        size_help.set_line_wrap(True)\n        size_row.pack_start(size_help, False, False, 0)\n',
)
old_advanced = '''        self._label(grid, "Boot volume label", 3)\n        self.volume_label = Gtk.Entry()\n        self.volume_label.set_max_length(11)\n        self.volume_label.set_text("RUFUS-LIVE")\n        self.volume_label.connect("changed", self.selection_changed)\n        grid.attach(self.volume_label, 1, 3, 2, 1)\n\n        self._label(grid, "Boot-time validation", 4)\n        runtime_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)\n        self.runtime_uefi_validation = Gtk.CheckButton(label="Validate media at UEFI boot")\n        self.runtime_uefi_validation.set_active(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        self.runtime_uefi_validation.connect("toggled", self.selection_changed)\n        runtime_box.pack_start(self.runtime_uefi_validation, False, False, 0)\n        runtime_warning = Gtk.Label(label=(\n            "Unsigned development loader — Secure Boot compatibility is not established"\n        ))\n        runtime_warning.set_xalign(0)\n        runtime_warning.set_line_wrap(True)\n        runtime_box.pack_start(runtime_warning, False, False, 0)\n        grid.attach(runtime_box, 1, 4, 2, 1)\n'''
new_advanced = '''        advanced = Gtk.Expander(label="Advanced options")\n        advanced_grid = Gtk.Grid(column_spacing=12, row_spacing=10)\n        advanced_grid.set_border_width(10)\n        advanced.add(advanced_grid)\n        outer.pack_start(advanced, False, False, 0)\n\n        self._label(advanced_grid, "USB name", 0)\n        self.volume_label = Gtk.Entry()\n        self.volume_label.set_max_length(11)\n        self.volume_label.set_text("RUFUS-LIVE")\n        self.volume_label.set_tooltip_text("The short name shown for the writable boot partition.")\n        self.volume_label.connect("changed", self.selection_changed)\n        advanced_grid.attach(self.volume_label, 1, 0, 2, 1)\n\n        self._label(advanced_grid, "Development validation", 1)\n        runtime_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)\n        self.runtime_uefi_validation = Gtk.CheckButton(label="Check media files during ARM64 UEFI boot")\n        self.runtime_uefi_validation.set_active(False)\n        self.runtime_uefi_validation.set_sensitive(False)\n        self.runtime_uefi_validation.connect("toggled", self.selection_changed)\n        runtime_box.pack_start(self.runtime_uefi_validation, False, False, 0)\n        runtime_warning = Gtk.Label(label=(\n            "For development testing only. The validation loader is unsigned and may not work with Secure Boot."\n        ))\n        runtime_warning.set_xalign(0)\n        runtime_warning.set_line_wrap(True)\n        runtime_box.pack_start(runtime_warning, False, False, 0)\n        advanced_grid.attach(runtime_box, 1, 1, 2, 1)\n'''
replace_once("gui/rufusarm64_persistence.py", old_advanced, new_advanced)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        frame = Gtk.Frame(label="Mandatory compatibility analysis")\n',
    '        frame = Gtk.Frame(label="Check compatibility")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '            "Analysis mounts only the identity-bound ISO in a private read-only workspace. The USB is not opened. "\n            "Creation remains disabled until the current image, target capacity, and requested size pass."\n',
    '            "This check reads the ISO without changing the USB. It confirms that the selected image supports "\n            "persistence and that the USB has enough space."\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.analyze_button = Gtk.Button(label="Analyze selected image")\n',
    '        self.analyze_button = Gtk.Button(label="Check ISO and USB")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.summary = Gtk.Label(label="Choose an ISO and removable USB, then run the mandatory analysis.")\n',
    '        self.summary = Gtk.Label(label="Choose an ISO and USB drive, then check compatibility.")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.detail = Gtk.Label(label="No destructive action is available until analysis succeeds.")\n',
    '        self.detail = Gtk.Label(label="The USB cannot be erased until the compatibility check succeeds.")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.create_button = Gtk.Button(label="Erase and create persistent USB")\n',
    '        self.create_button = Gtk.Button(label="Create persistent USB")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '            self.summary.set_text("Selection changed. Run compatibility analysis again before creation.")\n',
    '            self.summary.set_text("Selection changed. Check compatibility again before creating the USB.")\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '                text = plan_summary(plan, human_bytes)\n                self.summary.set_text(text)\n                self.append_log(text)\n',
    '                text = user_plan_summary(plan, human_bytes)\n                self.summary.set_text(text)\n                self.append_log(technical_plan_summary(plan, human_bytes))\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '            f"{plan_summary(self.plan, human_bytes)}"\n',
    '            f"{user_plan_summary(self.plan, human_bytes)}"\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        dialog.add_button("Erase and create persistent USB", Gtk.ResponseType.OK)\n',
    '        dialog.add_button("Erase USB and create", Gtk.ResponseType.OK)\n',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '        self.append_log(plan_summary(self.plan, human_bytes))\n',
    '        self.append_log(technical_plan_summary(self.plan, human_bytes))\n',
)
old_complete = '''            self.message(\n                "Persistent live media was created and checked."\n                f"{runtime_note}\\n\\nBoot it and run:\\n\\n"\n                "sudo rufusarm64-cli qualify start --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-initial.json\\n\\n"\n                "Reboot the same USB, then run qualify verify with a new output file. Until that passes, treat this image/hardware combination as unqualified.",\n                Gtk.MessageType.INFO,\n            )\n'''
new_complete = '''            self.append_log(\n                "Optional technical qualification commands are documented in the persistent live USB user guide."\n            )\n            self.message(\n                "Persistent live media was created and checked."\n                f"{runtime_note}\\n\\nTest persistence with these steps:\\n\\n"\n                f"{completion_checklist()}\\n\\n"\n                "Keep important files backed up elsewhere; a persistent live USB is not a normal installation.",\n                Gtk.MessageType.INFO,\n            )\n'''
replace_once("gui/rufusarm64_persistence.py", old_complete, new_complete)

# Tests for user-facing text remain pure and do not require GTK.
test = root / "gui/test_persistence_logic.py"
text = test.read_text()
text = text.replace(
    "    normalize_plan,\n)",
    "    normalize_plan,\n    technical_plan_summary,\n    user_plan_summary,\n    completion_checklist,\n)",
    1,
)
insert = '''\n    def test_user_summary_hides_boot_internals(self):\n        plan = {\n            "name": "Ubuntu 24.04", "family": "ubuntu-casper", "filesystem": "ext4",\n            "label": "casper-rw", "parameter": "persistent", "size": 16 * 1024**3,\n            "target_size": 64 * 1024**3, "patch_paths": ["boot/grub/grub.cfg"],\n        }\n        summary = user_plan_summary(plan, lambda value: f"{value // 1024**3} GiB")\n        self.assertIn("Ubuntu 24.04", summary)\n        self.assertIn("16 GiB", summary)\n        self.assertNotIn("casper-rw", summary)\n        self.assertNotIn("grub.cfg", summary)\n        technical = technical_plan_summary(plan, lambda value: f"{value // 1024**3} GiB")\n        self.assertIn("casper-rw", technical)\n        self.assertIn("grub.cfg", technical)\n\n    def test_completion_checklist_is_plain_language(self):\n        checklist = completion_checklist()\n        self.assertIn("boot from the new USB", checklist)\n        self.assertIn("test file", checklist)\n        self.assertIn("still present", checklist)\n        self.assertNotIn("rufusarm64-cli", checklist)\n'''
text = text.replace("\n\nif __name__ == \"__main__\":", insert + "\n\nif __name__ == \"__main__\":", 1)
test.write_text(text)

# Rewrite the user workflow section and make advanced qualification explicitly optional.
guide = root / "docs/persistence-user-guide.md"
text = guide.read_text()
start = text.index("## Creation workflow")
end = text.index("## Qualification after creation", start)
workflow = '''## Creation workflow\n\n1. Open **Create Persistent Live USB** from the RufusArm64 application entry, or run `rufusarm64 --persistence`.\n2. Choose the Ubuntu or Debian ISO.\n3. Select the exact removable USB drive.\n4. Choose how much space to keep for saved files and settings. Leave the value at zero to use the recommended available space.\n5. Select **Check ISO and USB**. This read-only check does not open or modify the USB.\n6. When RufusArm64 reports that the image is supported, select **Create persistent USB**.\n7. Confirm the exact USB in the final erase warning, then keep it connected until creation completes.\n\nAdvanced options are collapsed by default. Most users should leave the USB name unchanged and leave development boot-time validation disabled. The privileged helper still repeats all source and target identity checks, removable-drive checks, filesystem verification, and final buffer flushing before reporting success.\n\nAfter creation, boot from the USB, create a small test file in the live system's Home folder, restart from the same USB, and confirm that the file is still present. This simple reboot test is the practical confirmation that persistence works on that computer.\n\n'''
text = text[:start] + workflow + text[end:]
text = text.replace("## Qualification after creation\n", "## Optional technical qualification after creation\n", 1)
guide.write_text(text)
