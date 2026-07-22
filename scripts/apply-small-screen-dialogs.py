#!/usr/bin/env python3
"""Apply the reviewed small-screen GTK dialog layout changes."""

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}\n---\n{old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_in_class(path: Path, class_name: str, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    marker = f"class {class_name}("
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"{path}: class {class_name} not found")
    end = text.find("\nclass ", start + len(marker))
    if end < 0:
        end = len(text)
    segment = text[start:end]
    count = segment.count(old)
    if count != 1:
        raise SystemExit(f"{path}:{class_name}: expected one match, found {count}\n---\n{old}")
    segment = segment.replace(old, new, 1)
    path.write_text(text[:start] + segment + text[end:], encoding="utf-8")


dialogs = Path("gui/rufusarm64_device_qualify_dialog.py")
replace_in_class(
    dialogs,
    "DeviceQualificationDialog",
    '''        self.set_default_size(700, 520)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)
''',
    '''        self.set_default_size(700, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        detail_scroll.set_min_content_height(120)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_scroll.add(detail_box)
        box.pack_start(detail_scroll, True, True, 0)
''',
)
for old, new in (
    ("        box.pack_start(intro, False, False, 0)\n\n        row = Gtk.Box", "        detail_box.pack_start(intro, False, False, 0)\n\n        row = Gtk.Box"),
    ("        box.pack_start(row, False, False, 0)\n\n        self.plan_label", "        detail_box.pack_start(row, False, False, 0)\n\n        self.plan_label"),
    ("        box.pack_start(self.plan_label, False, False, 0)\n\n        warning = Gtk.InfoBar()", "        detail_box.pack_start(self.plan_label, False, False, 0)\n\n        warning = Gtk.InfoBar()"),
    ("        box.pack_start(warning, False, False, 0)\n\n        confirm_row", "        detail_box.pack_start(warning, False, False, 0)\n\n        confirm_row"),
):
    replace_in_class(dialogs, "DeviceQualificationDialog", old, new)
replace_in_class(
    dialogs,
    "DeviceQualificationDialog",
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_vexpand(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No qualification report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, True, True, 0)
''',
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No qualification report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)
''',
)

replace_in_class(
    dialogs,
    "DriveImageBackupDialog",
    '''        self.set_default_size(780, 620)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)
''',
    '''        self.set_default_size(760, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        detail_scroll.set_min_content_height(120)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_scroll.add(detail_box)
        box.pack_start(detail_scroll, True, True, 0)
''',
)
for old, new in (
    ("        box.pack_start(intro, False, False, 0)\n\n        destination_row", "        detail_box.pack_start(intro, False, False, 0)\n\n        destination_row"),
    ("        box.pack_start(destination_row, False, False, 0)\n\n        self.plan_label", "        detail_box.pack_start(destination_row, False, False, 0)\n\n        self.plan_label"),
    ("        box.pack_start(self.plan_label, False, False, 0)\n\n        note = Gtk.InfoBar()", "        detail_box.pack_start(self.plan_label, False, False, 0)\n\n        note = Gtk.InfoBar()"),
    ("        box.pack_start(note, False, False, 0)\n\n        self.confirm_label", "        detail_box.pack_start(note, False, False, 0)\n\n        self.confirm_label"),
):
    replace_in_class(dialogs, "DriveImageBackupDialog", old, new)
replace_in_class(
    dialogs,
    "DriveImageBackupDialog",
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_vexpand(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No backup report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, True, True, 0)
''',
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No backup report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)
''',
)

freedos = Path("gui/rufusarm64_freedos_dialog.py")
replace_in_class(
    freedos,
    "FreeDOSFormatDialog",
    '''        self.set_default_size(820, 690)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)
''',
    '''        self.set_default_size(780, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        detail_scroll.set_min_content_height(120)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_scroll.add(detail_box)
        box.pack_start(detail_scroll, True, True, 0)
''',
)
for old, new in (
    ("        box.pack_start(title, False, False, 0)\n\n        intro = Gtk.Label", "        detail_box.pack_start(title, False, False, 0)\n\n        intro = Gtk.Label"),
    ("        box.pack_start(intro, False, False, 0)\n\n        controls = Gtk.Grid", "        detail_box.pack_start(intro, False, False, 0)\n\n        controls = Gtk.Grid"),
    ("        box.pack_start(controls, False, False, 0)\n        controls.attach", "        detail_box.pack_start(controls, False, False, 0)\n        controls.attach"),
    ("        box.pack_start(self.plan_label, False, False, 0)\n\n        warning = Gtk.InfoBar()", "        detail_box.pack_start(self.plan_label, False, False, 0)\n\n        warning = Gtk.InfoBar()"),
    ("        box.pack_start(warning, False, False, 0)\n\n        self.confirm_label", "        detail_box.pack_start(warning, False, False, 0)\n\n        self.confirm_label"),
):
    replace_in_class(freedos, "FreeDOSFormatDialog", old, new)
replace_in_class(
    freedos,
    "FreeDOSFormatDialog",
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_vexpand(True)
        self.result = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result.get_buffer().set_text("No FreeDOS report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, True, True, 0)
''',
    '''        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result.get_buffer().set_text("No FreeDOS report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)
''',
)

qualification_test = Path("gui/test_device_qualify_dialog.py")
replace_once(
    qualification_test,
    '''    def test_reports_are_normalized_and_rendered(self):
        self.assertIn("normalize_plan", self.qualification_source)
        self.assertIn("normalize_report", self.qualification_source)
        self.assertIn("report_summary", self.qualification_source)
        self.assertIn("json.dumps(payload, indent=2, sort_keys=True)", self.qualification_source)

''',
    '''    def test_reports_are_normalized_and_rendered(self):
        self.assertIn("normalize_plan", self.qualification_source)
        self.assertIn("normalize_report", self.qualification_source)
        self.assertIn("report_summary", self.qualification_source)
        self.assertIn("json.dumps(payload, indent=2, sort_keys=True)", self.qualification_source)

    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(700, 560)", self.qualification_source)
        self.assertIn("self.set_resizable(True)", self.qualification_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.qualification_source)
        self.assertIn("detail_box.pack_start(warning, False, False, 0)", self.qualification_source)
        self.assertIn("box.pack_start(confirm_row, False, False, 0)", self.qualification_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.qualification_source)
        self.assertIn("result_scroll.set_min_content_height(140)", self.qualification_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.qualification_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.qualification_source)
        self.assertLess(
            self.qualification_source.index('self.add_button("Close", Gtk.ResponseType.CLOSE)'),
            self.qualification_source.index("detail_scroll = Gtk.ScrolledWindow()"),
        )

''',
)

backup_test = Path("gui/test_device_backup_dialog.py")
replace_once(
    backup_test,
    '''    def test_progress_final_report_and_destination_are_revalidated(self):
        self.assertIn("start_new_session=True", self.backup_class_source)
''',
    '''    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(760, 560)", self.backup_class_source)
        self.assertIn("self.set_resizable(True)", self.backup_class_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.backup_class_source)
        self.assertIn("detail_box.pack_start(note, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(self.confirm_label, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(self.confirmation, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.backup_class_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.backup_class_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.backup_class_source)

    def test_progress_final_report_and_destination_are_revalidated(self):
        self.assertIn("start_new_session=True", self.backup_class_source)
''',
)

freedos_test = Path("gui/test_freedos_dialog.py")
replace_once(
    freedos_test,
    '''    def test_graphical_execution_stays_inside_guarded_contract(self):
        self.assertIn("--expected-identity", self.logic_source)
''',
    '''    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(780, 560)", self.dialog_class_source)
        self.assertIn("self.set_resizable(True)", self.dialog_class_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.dialog_class_source)
        self.assertIn("detail_box.pack_start(warning, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(self.confirm_label, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(self.confirmation, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.dialog_class_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.dialog_class_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.dialog_class_source)

    def test_graphical_execution_stays_inside_guarded_contract(self):
        self.assertIn("--expected-identity", self.logic_source)
''',
)
