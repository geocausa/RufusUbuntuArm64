#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / "gui/rufusarm64.py"
text = path.read_text()


def once(old, new):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one anchor, found {count}: {old[:80]!r}")
    text = text.replace(old, new, 1)

once(
    "from rufusarm64_checksums import ChecksumDialog\n",
    "from rufusarm64_checksums import ChecksumDialog\nfrom rufusarm64_persistence_logic import (\n"
    "    build_create_command as build_persistence_create_command,\n"
    "    completion_checklist,\n"
    "    normalize_plan as normalize_persistence_plan,\n"
    "    technical_plan_summary,\n"
    "    user_plan_summary,\n"
    ")\n",
)
once(
    'PERSISTENCE_LAUNCHER = "/usr/bin/rufusarm64-persistence"\n',
    'PERSISTENCE_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"\n',
)

# Keep the old launcher resolver out of the user path; it is no longer called.
start = text.index("def persistence_launcher_path():")
end = text.index("\n\ndef config_path():", start)
text = text[:start] + text[end + 2:]

once(
    "        self.download_result = {}\n        self.settings = self.load_settings()\n",
    "        self.download_result = {}\n"
    "        self.persistence_plan = None\n"
    "        self.persistence_plan_key = None\n"
    "        self.persistence_source_identity = \"\"\n"
    "        self.settings = self.load_settings()\n",
)
once(
    '        self.download_button = Gtk.Button(label="Download…")\n'
    '        self.download_button.set_tooltip_text("Choose an image from a locally supplied, Ed25519-signed catalog")\n'
    '        self.download_button.connect("clicked", self.open_acquisition)\n',
    '        self.download_button = Gtk.Button(label="Download unavailable")\n'
    '        self.download_button.set_sensitive(False)\n'
    '        self.download_button.set_tooltip_text("Direct operating-system downloads are not implemented. Download the ISO from its official website, then select it here.")\n',
)
once(
    '        self.target_combo = Gtk.ComboBoxText()\n        self.target_combo.set_hexpand(True)\n',
    '        self.target_combo = Gtk.ComboBoxText()\n        self.target_combo.set_hexpand(True)\n        self.target_combo.connect("changed", self.persistence_selection_changed)\n',
)
old_panel = '''        persistence = Gtk.Expander(label="Persistent Linux media (guarded creator)")
        persistence_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        persistence_box.set_margin_top(8)
        persistence_intro = Gtk.Label(label=(
            "The ordinary Create USB button preserves Linux images byte-for-byte and does not add persistence. "
            "Check compatibility here, then open the guarded creator to build a writable FAT32 plus ext4 persistent USB."
        ))
        persistence_intro.set_xalign(0)
        persistence_intro.set_line_wrap(True)
        persistence_box.pack_start(persistence_intro, False, False, 0)
        persistence_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.persistence_button = Gtk.Button(label="Check persistence compatibility…")
        self.persistence_button.connect("clicked", self.analyze_persistence)
        persistence_actions.pack_start(self.persistence_button, False, False, 0)
        self.open_persistence_button = Gtk.Button(label="Open Persistent USB Creator…")
        self.open_persistence_button.connect("clicked", self.open_persistence_creator)
        persistence_actions.pack_start(self.open_persistence_button, False, False, 0)
        persistence_box.pack_start(persistence_actions, False, False, 0)
        self.persistence_summary = Gtk.Label(label="Select a recognized Linux ISOHybrid image and USB drive.")
        self.persistence_summary.set_xalign(0)
        self.persistence_summary.set_line_wrap(True)
        self.persistence_summary.set_selectable(True)
        self.persistence_summary.get_style_context().add_class("dim-label")
        persistence_box.pack_start(self.persistence_summary, False, False, 0)
        persistence.add(persistence_box)
        outer.pack_start(persistence, False, False, 0)
'''
new_panel = '''        persistence = Gtk.Expander(label="Persistent storage")
        persistence_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        persistence_box.set_margin_top(8)
        self.persistence_enabled = Gtk.CheckButton(label="Keep files and settings across reboots")
        self.persistence_enabled.set_active(False)
        self.persistence_enabled.connect("toggled", self.persistence_selection_changed)
        persistence_box.pack_start(self.persistence_enabled, False, False, 0)
        persistence_intro = Gtk.Label(label=(
            "Available for supported Ubuntu and Debian live ISOs. RufusArm64 checks compatibility before the same Create USB button can use the guarded persistent-media writer."
        ))
        persistence_intro.set_xalign(0)
        persistence_intro.set_line_wrap(True)
        persistence_intro.set_margin_start(28)
        persistence_intro.get_style_context().add_class("dim-label")
        persistence_box.pack_start(persistence_intro, False, False, 0)
        persistence_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.persistence_size = Gtk.SpinButton.new_with_range(0, 1024, 1)
        self.persistence_size.set_value(int(self.settings.get("persistence_size_gib", 0) or 0))
        self.persistence_size.connect("value-changed", self.persistence_selection_changed)
        persistence_actions.pack_start(Gtk.Label(label="Saved-change space"), False, False, 0)
        persistence_actions.pack_start(self.persistence_size, False, False, 0)
        persistence_actions.pack_start(Gtk.Label(label="GiB (0 = recommended available space)"), False, False, 0)
        self.persistence_button = Gtk.Button(label="Check compatibility")
        self.persistence_button.connect("clicked", self.analyze_persistence)
        persistence_actions.pack_start(self.persistence_button, False, False, 0)
        persistence_box.pack_start(persistence_actions, False, False, 0)
        self.persistence_summary = Gtk.Label(label="Persistence is off. The image will be written in its normal mode.")
        self.persistence_summary.set_xalign(0)
        self.persistence_summary.set_line_wrap(True)
        self.persistence_summary.set_selectable(True)
        self.persistence_summary.get_style_context().add_class("dim-label")
        persistence_box.pack_start(self.persistence_summary, False, False, 0)
        persistence.add(persistence_box)
        outer.pack_start(persistence, False, False, 0)
'''
once(old_panel, new_panel)

# Persist the unified control.
once(
    '        self.settings["bad_block_check"] = self.bad_block_check.get_active()\n',
    '        self.settings["bad_block_check"] = self.bad_block_check.get_active()\n'
    '        self.settings["persistence_size_gib"] = self.persistence_size.get_value_as_int()\n',
)

# Replace control-state tail with persistence-aware behavior.
once(
    '        self.start_button.set_sensitive(not self.busy and bool(self.devices) and bool(info.get("recognized")))\n'
    '        self.persistence_button.set_sensitive(not self.busy and bool(self.devices) and bool(info.get("recognized")) and info.get("mode") == "raw")\n'
    '        if info.get("mode") != "raw":\n'
    '            self.persistence_summary.set_text("Select a recognized Linux ISOHybrid image and USB drive.")\n'
    '        self.update_verify_warning()\n',
    '        raw_ready = bool(self.devices) and bool(info.get("recognized")) and info.get("mode") == "raw"\n'
    '        persistence_on = self.persistence_enabled.get_active()\n'
    '        self.persistence_enabled.set_sensitive(not self.busy and raw_ready)\n'
    '        self.persistence_size.set_sensitive(not self.busy and raw_ready and persistence_on)\n'
    '        self.persistence_button.set_sensitive(not self.busy and raw_ready and persistence_on)\n'
    '        plan_ready = self.persistence_plan is not None and self.persistence_plan_key == self.current_persistence_key(allow_missing=True)\n'
    '        self.start_button.set_sensitive(not self.busy and bool(self.devices) and bool(info.get("recognized")) and (not persistence_on or plan_ready))\n'
    '        self.verify.set_sensitive(not self.busy and not persistence_on)\n'
    '        if persistence_on and not plan_ready:\n'
    '            self.persistence_summary.set_text("Check compatibility for the current ISO, USB drive, and saved-change size before creating the USB.")\n'
    '        elif not persistence_on:\n'
    '            self.persistence_summary.set_text("Persistence is off. The image will be written in its normal mode.")\n'
    '        self.update_verify_warning()\n',
)

# Remove visible secondary launcher and add plan invalidation helpers.
old_launcher = '''    def open_persistence_creator(self, *_):
        if self.busy:
            return
        try:
            subprocess.Popen([persistence_launcher_path()], start_new_session=True)
        except OSError as exc:
            self.message(f"Could not open the persistent USB creator: {exc}", Gtk.MessageType.ERROR)

'''
new_helpers = '''    def current_persistence_key(self, allow_missing=False):
        image = self.image_chooser.get_filename() or ""
        index = self.target_combo.get_active()
        if not image or not (0 <= index < len(self.devices)):
            return None if allow_missing else ()
        device = self.devices[index]
        return (
            os.path.realpath(os.path.abspath(image)),
            str(device.get("identity") or ""),
            int(device.get("size") or 0),
            self.persistence_size.get_value_as_int(),
        )

    def persistence_selection_changed(self, *_):
        if getattr(self, "persistence_plan", None) is not None and self.persistence_plan_key != self.current_persistence_key(allow_missing=True):
            self.persistence_plan = None
            self.persistence_plan_key = None
            self.persistence_source_identity = ""
        if getattr(self, "inspection", {}).get("recognized"):
            self.apply_inspection(self.inspection)

'''
once(old_launcher, new_helpers)

# Use in-window size and bind the result to the exact current selection.
once(
    '        dialog = PersistencePlanDialog(self, self.settings)\n'
    '        response = dialog.run()\n'
    '        size_gib = dialog.values() if response == Gtk.ResponseType.OK else None\n'
    '        dialog.destroy()\n'
    '        if size_gib is None:\n'
    '            return\n'
    '        self.settings["persistence_size_gib"] = size_gib\n',
    '        if not self.persistence_enabled.get_active():\n'
    '            self.message("Turn on Keep files and settings across reboots first.", Gtk.MessageType.INFO)\n'
    '            return\n'
    '        size_gib = self.persistence_size.get_value_as_int()\n'
    '        self.settings["persistence_size_gib"] = size_gib\n',
)
once(
    '        self.active_job = "persistence-plan"\n',
    '        plan_key = self.current_persistence_key()\n'
    '        self.active_job = "persistence-plan"\n',
)
once(
    '        threading.Thread(target=self.run_persistence_plan, args=(command,), daemon=True).start()\n',
    '        threading.Thread(target=self.run_persistence_plan, args=(command, plan_key, source_identity), daemon=True).start()\n',
)
once(
    '    def run_persistence_plan(self, command):\n',
    '    def run_persistence_plan(self, command, plan_key, source_identity):\n',
)
once(
    '            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error)\n',
    '            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error, plan_key, source_identity)\n',
)
once(
    '            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc))\n',
    '            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc), plan_key, source_identity)\n',
)
once(
    '    def finish_persistence_plan(self, return_code, payload, error):\n',
    '    def finish_persistence_plan(self, return_code, payload, error, plan_key, source_identity):\n',
)
once(
    '                summary = persistence_plan_summary(payload)\n',
    '                plan = normalize_persistence_plan(payload)\n'
    '                if plan_key != self.current_persistence_key(allow_missing=True):\n'
    '                    raise ValueError("The ISO, USB drive, or persistence size changed while compatibility was being checked.")\n'
    '                summary = user_plan_summary(plan, human_bytes)\n',
)
once(
    '                self.persistence_summary.set_text(summary)\n'
    '                self.progress.set_fraction(1.0)\n'
    '                self.progress.set_text("Persistence compatibility confirmed")\n'
    '                self.progress_detail.set_text("The private read-only ISO mount was removed. Open the guarded persistent USB creator to continue.")\n'
    '                self.append_log(summary)\n',
    '                self.persistence_plan = plan\n'
    '                self.persistence_plan_key = plan_key\n'
    '                self.persistence_source_identity = source_identity\n'
    '                self.persistence_summary.set_text(summary)\n'
    '                self.progress.set_fraction(1.0)\n'
    '                self.progress.set_text("Persistence compatibility confirmed")\n'
    '                self.progress_detail.set_text("The read-only check is complete. The same Create USB button is now ready for persistent media.")\n'
    '                self.append_log(technical_plan_summary(plan, human_bytes))\n'
    '                self.apply_inspection(self.inspection)\n',
)

# Guard the unified start path and change the confirmation summary.
once(
    '        options = {}\n        if self.inspection.get("windows_options"):\n',
    '        persistence_requested = self.persistence_enabled.get_active()\n'
    '        if persistence_requested:\n'
    '            if self.inspection.get("mode") != "raw":\n'
    '                self.message("Persistence is available only for supported Ubuntu or Debian live ISOs.", Gtk.MessageType.ERROR)\n'
    '                return\n'
    '            if self.persistence_plan is None or self.persistence_plan_key != self.current_persistence_key(allow_missing=True):\n'
    '                self.message("Check persistence compatibility for the current ISO, USB drive, and size first.", Gtk.MessageType.INFO)\n'
    '                return\n'
    '        options = {}\n        if self.inspection.get("windows_options"):\n',
)
once(
    '        summary = self.inspection.get("description", "Bootable media")\n',
    '        summary = user_plan_summary(self.persistence_plan, human_bytes) if persistence_requested else self.inspection.get("description", "Bootable media")\n',
)
once(
    '        verify_requested = self.verify.get_active()\n',
    '        verify_requested = True if persistence_requested else self.verify.get_active()\n',
)
once(
    '        self.active_job = "writer"\n',
    '        self.active_job = "writer"\n',
)
once(
    '        self.active_mode = self.inspection.get("mode", "")\n',
    '        self.active_mode = "linux-persistent" if persistence_requested else self.inspection.get("mode", "")\n',
)
once(
    '        if self.inspection.get("mode") == "windows":\n'
    '            layout_summary = f"{partition_scheme.upper()} / {self.target_system_combo.get_active_text()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters"\n'
    '        else:\n'
    '            layout_summary = "From image / From image / From image"\n',
    '        if persistence_requested:\n'
    '            layout_summary = f"GPT / UEFI / FAT32 boot + {human_bytes(self.persistence_plan[\"size\"])} ext4 persistence"\n'
    '        elif self.inspection.get("mode") == "windows":\n'
    '            layout_summary = f"{partition_scheme.upper()} / {self.target_system_combo.get_active_text()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters"\n'
    '        else:\n'
    '            layout_summary = "From image / From image / From image"\n',
)
old_command = '''        try:
            command = build_writer_command(
                PKEXEC,
                helper_path(),
                image,
                path,
                identity,
                verify_requested,
                self.cancel_path,
                label,
                options,
                partition_scheme,
                target_system,
                filesystem,
                cluster_size,
                driver_folder,
                dbx_file,
                quick_format,
                bad_block_check,
            )
'''
new_command = '''        try:
            if persistence_requested:
                resolved_image, source_identity = inspect_source_identity(image)
                if source_identity != self.persistence_source_identity:
                    raise ValueError("The selected ISO changed after persistence compatibility was checked. Check compatibility again.")
                command = build_persistence_create_command(
                    PKEXEC,
                    PERSISTENCE_HELPER,
                    resolved_image,
                    source_identity,
                    path,
                    identity,
                    self.persistence_size.get_value_as_int(),
                    "RUFUS-LIVE",
                    self.cancel_path,
                    False,
                )
            else:
                command = build_writer_command(
                    PKEXEC,
                    helper_path(),
                    image,
                    path,
                    identity,
                    verify_requested,
                    self.cancel_path,
                    label,
                    options,
                    partition_scheme,
                    target_system,
                    filesystem,
                    cluster_size,
                    driver_folder,
                    dbx_file,
                    quick_format,
                    bad_block_check,
                )
'''
once(old_command, new_command)

# Unified completion message.
once(
    '            self.message(success_message(self.active_mode, self.active_verify_requested, self.active_filesystem), Gtk.MessageType.INFO)\n',
    '            if self.active_mode == "linux-persistent":\n'
    '                self.message("Persistent live USB created and checked.\\n\\nTest it with these steps:\\n\\n" + completion_checklist(), Gtk.MessageType.INFO)\n'
    '            else:\n'
    '                self.message(success_message(self.active_mode, self.active_verify_requested, self.active_filesystem), Gtk.MessageType.INFO)\n',
)

path.write_text(text)

# Update user-facing documentation to describe one application and no public download feature.
guide = root / "docs/persistence-user-guide.md"
g = guide.read_text()
g = g.replace(
    "RufusArm64 installs one visible desktop application entry. Open its **Create Persistent Live USB** action to start the guarded persistence wizard, or run:\n\n```text\nrufusarm64 --persistence\n```\n\nThe implementation-only command remains available as:\n\n```text\nrufusarm64-persistence\n```\n\nOnly the guarded persistence wizard presents **Create persistent USB** and invokes the restricted persistence helper. Keeping that helper separate internally prevents the ordinary writer from silently gaining persistence privileges.\n",
    "RufusArm64 presents persistence in the main application window. Select the ISO and USB drive, expand **Persistent storage**, turn on saved changes, check compatibility, and use the same **Create USB** button. The restricted persistence helper remains separate internally so the ordinary writer does not silently gain persistence privileges.\n",
)
g = g.replace(
    "1. Open **Create Persistent Live USB** from the RufusArm64 application entry, or run `rufusarm64 --persistence`.\n2. Choose the Ubuntu or Debian ISO.\n",
    "1. Open RufusArm64.\n2. Choose the Ubuntu or Debian ISO.\n",
)
g = g.replace(
    "5. Select **Check ISO and USB**. This read-only check does not open or modify the USB.\n6. When RufusArm64 reports that the image is supported, select **Create persistent USB**.\n",
    "5. Expand **Persistent storage**, enable saved changes, and select **Check compatibility**. This read-only check does not open or modify the USB.\n6. When RufusArm64 reports that the image is supported, select the normal **Create USB** button.\n",
)
guide.write_text(g)

# Add source-level regression tests for the product decisions and helper boundary.
test = root / "gui/test_unified_persistence_ui.py"
test.write_text('''import pathlib\nimport unittest\n\n\nclass UnifiedPersistenceUISourceTests(unittest.TestCase):\n    @classmethod\n    def setUpClass(cls):\n        cls.source = pathlib.Path("gui/rufusarm64.py").read_text(encoding="utf-8")\n\n    def test_download_is_disabled_and_not_connected(self):\n        self.assertIn('Gtk.Button(label="Download unavailable")', self.source)\n        self.assertIn('self.download_button.set_sensitive(False)', self.source)\n        self.assertNotIn('self.download_button.connect("clicked", self.open_acquisition)', self.source)\n\n    def test_persistence_stays_in_main_window(self):\n        self.assertIn('Gtk.Expander(label="Persistent storage")', self.source)\n        self.assertIn('Keep files and settings across reboots', self.source)\n        self.assertNotIn('Open Persistent USB Creator…', self.source)\n        self.assertNotIn('subprocess.Popen([persistence_launcher_path()]', self.source)\n\n    def test_same_start_path_uses_restricted_helper(self):\n        self.assertIn('build_persistence_create_command(', self.source)\n        self.assertIn('PERSISTENCE_HELPER', self.source)\n        self.assertIn('self.active_mode = "linux-persistent"', self.source)\n        self.assertIn('completion_checklist()', self.source)\n\n\nif __name__ == "__main__":\n    unittest.main()\n''')
