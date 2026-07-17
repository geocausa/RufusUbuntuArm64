#!/usr/bin/env python3
from pathlib import Path
import re

path = Path("gui/rufusarm64.py")
text = path.read_text(encoding="utf-8")


def literal(old, new):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one literal match, found {count}")
    text = text.replace(old, new, 1)


def methods(start, end, replacement):
    global text
    pattern = rf"(?ms)^    def {re.escape(start)}\(.*?(?=^    def {re.escape(end)}\()"
    text, count = re.subn(pattern, replacement.rstrip() + "\n\n", text, count=1)
    if count != 1:
        raise SystemExit(f"expected one method range {start}..{end}, found {count}")


literal(
    "        self.channel_timer_id = 0\n        self.closed = False\n",
    "        self.channel_timer_id = 0\n        self.catalog_verifying = False\n        self.catalog_generation = 0\n        self.closed = False\n",
)
literal(
    "    def refresh_channel(self, *_):\n        if self.channel_refreshing or self.closed:\n            return False\n",
    "    def refresh_channel(self, *_):\n        if self.channel_refreshing or self.catalog_verifying or self.closed:\n            return False\n",
)
methods(
    "verify_catalog",
    "_populate_images",
    '''    def verify_catalog(self, *_):
        if self.channel_refreshing or self.catalog_verifying or self.closed:
            return
        selection = (
            self.catalog.get_filename(),
            self.signature.get_filename(),
            self.public_key.get_filename(),
        )
        try:
            command = build_acquisition_list_command(helper_path(), *selection)
        except Exception as exc:
            self.catalog_status.set_text(f"Local catalog rejected: {exc}")
            if self.mode == "manual":
                self._populate_images([], "", {})
            return
        self.catalog_generation += 1
        generation = self.catalog_generation
        self.catalog_verifying = True
        self.verify_button.set_sensitive(False)
        self.channel_button.set_sensitive(False)
        self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(False)
        self.catalog_status.set_text("Verifying the local signed catalog…")
        threading.Thread(
            target=self._run_catalog_verify,
            args=(command, selection, generation),
            daemon=True,
        ).start()

    def _run_catalog_verify(self, command, selection, generation):
        images = []
        error = ""
        try:
            result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=20)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Catalog verification failed")
            images = normalize_acquisition_images(json.loads(result.stdout))
        except Exception as exc:
            error = str(exc)
        GLib.idle_add(self._finish_catalog_verify, images, error, selection, generation)

    def _finish_catalog_verify(self, images, error, selection, generation):
        if self.closed or generation != self.catalog_generation:
            return False
        self.catalog_verifying = False
        self.verify_button.set_sensitive(not self.channel_refreshing)
        self.channel_button.set_sensitive(not self.channel_refreshing)
        current = (
            self.catalog.get_filename(),
            self.signature.get_filename(),
            self.public_key.get_filename(),
        )
        if current != selection:
            self.catalog_status.set_text("Local trust files changed while verification was running. Verify them again.")
            if self.mode == "manual":
                self._populate_images([], "", {})
            return False
        if error:
            self.catalog_status.set_text(f"Local catalog rejected: {error}")
            if self.mode == "manual":
                self._populate_images([], "", {})
            return False
        self.catalog_status.set_text(f"Local signature valid. {len(images)} downloadable image(s) are available.")
        self._populate_images(images, "manual", {})
        return False''',
)
literal(
    '        self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(bool(image and self.output.get_filename() and not self.channel_refreshing))\n',
    '        self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(\n            bool(image and self.output.get_filename() and not self.channel_refreshing and not self.catalog_verifying)\n        )\n',
)
path.write_text(text, encoding="utf-8")

path = Path("gui/test_source_structure.py")
text = path.read_text(encoding="utf-8")
marker = "    def test_audit_commands_and_package_assertions_are_not_duplicated(self):\n"
addition = '''    def test_slow_gui_subprocesses_use_workers_and_generation_guards(self):
        expected = {
            "rufusarm64.py": {
                "AcquisitionDialog": {
                    "verify_catalog": ("threading.Thread(",),
                    "_run_catalog_verify": ("subprocess.run(",),
                    "_finish_catalog_verify": ("generation != self.catalog_generation", "self.closed"),
                },
                "RufusWindow": {
                    "image_changed": ("threading.Thread(",),
                    "_run_image_inspection": ("subprocess.run(",),
                    "_finish_image_inspection": ("generation != self.inspection_generation", "self.closed"),
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                },
            },
            "rufusarm64_persistence.py": {
                "Window": {
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                },
            },
        }
        failures = []
        for filename, classes in expected.items():
            path = GUI_ROOT / filename
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            class_methods = {
                class_node.name: {
                    node.name: ast.get_source_segment(source, node) or ""
                    for node in class_node.body
                    if isinstance(node, ast.FunctionDef)
                }
                for class_node in tree.body
                if isinstance(class_node, ast.ClassDef)
            }
            for class_name, methods_ in classes.items():
                for method_name, required_fragments in methods_.items():
                    body = class_methods.get(class_name, {}).get(method_name, "")
                    if not body:
                        failures.append(f"{filename}:{class_name}.{method_name} is missing")
                        continue
                    if method_name in {"verify_catalog", "image_changed", "refresh_devices"} and "subprocess.run(" in body:
                        failures.append(f"{filename}:{class_name}.{method_name} blocks the GTK thread")
                    for fragment in required_fragments:
                        if fragment not in body:
                            failures.append(f"{filename}:{class_name}.{method_name} lacks {fragment!r}")
        self.assertEqual(failures, [], "\\n" + "\\n".join(failures))

'''
if text.count(marker) != 1:
    raise SystemExit(f"source-structure insertion marker count = {text.count(marker)}")
path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
