#!/usr/bin/env python3
from pathlib import Path


def replace_once(path_name, old, new):
    path = Path(path_name)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/rufusarm64.py",
    '''    def run_download(self, command):
        result_payload = {}
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            assert self.process.stdout is not None
            for raw in self.process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                if isinstance(payload, dict) and payload.get("event"):
                    GLib.idle_add(self.handle_event, payload)
                elif isinstance(payload, dict) and payload.get("path"):
                    result_payload = payload
            return_code = self.process.wait()
            GLib.idle_add(self.finish_download, return_code, result_payload)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Verified download failed: {exc}")
            GLib.idle_add(self.finish_download, 1, {})
        finally:
            self.process = None
''',
    '''    def run_download(self, command):
        result_payload = {}
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            self.process = process
            assert process.stdout is not None
            if self.cancel_requested and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            for raw in process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                if isinstance(payload, dict) and payload.get("event"):
                    GLib.idle_add(self.handle_event, payload)
                elif isinstance(payload, dict) and payload.get("path"):
                    result_payload = payload
            return_code = process.wait()
            GLib.idle_add(self.finish_download, return_code, result_payload)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Verified download failed: {exc}")
            GLib.idle_add(self.finish_download, 1, {})
        finally:
            if self.process is process:
                self.process = None
''',
)

replace_once(
    "gui/rufusarm64.py",
    '''    def run_persistence_plan(self, command):
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            stdout, stderr = self.process.communicate()
            return_code = self.process.returncode
            payload = json.loads(stdout) if return_code == 0 else {}
            error = stderr.strip() or stdout.strip() if return_code != 0 else ""
            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error)
        except Exception as exc:
            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc))
        finally:
            self.process = None
''',
    '''    def run_persistence_plan(self, command):
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            self.process = process
            stdout, stderr = process.communicate()
            return_code = process.returncode
            payload = json.loads(stdout) if return_code == 0 else {}
            error = stderr.strip() or stdout.strip() if return_code != 0 else ""
            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error)
        except Exception as exc:
            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc))
        finally:
            if self.process is process:
                self.process = None
''',
)

replace_once(
    "gui/rufusarm64.py",
    '''    def run_writer(self, command):
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert self.process.stdout is not None
            if self.cancel_requested and self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
            for raw in self.process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                GLib.idle_add(self.handle_event, event)
            return_code = self.process.wait()
            GLib.idle_add(self.finish, return_code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Failed to start the writer: {exc}")
            GLib.idle_add(self.finish, 1)
        finally:
            self.process = None
''',
    '''    def run_writer(self, command):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            self.process = process
            assert process.stdout is not None
            if self.cancel_requested and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            for raw in process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                GLib.idle_add(self.handle_event, event)
            return_code = process.wait()
            GLib.idle_add(self.finish, return_code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Failed to start the writer: {exc}")
            GLib.idle_add(self.finish, 1)
        finally:
            if self.process is process:
                self.process = None
''',
)

replace_once(
    "gui/rufusarm64_persistence.py",
    '''    def run_analysis(self, command, key):
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            stdout, stderr = self.process.communicate()
            code = self.process.returncode
            payload = json.loads(stdout) if code == 0 else {}
            error = (stderr.strip() or stdout.strip()) if code else ""
            GLib.idle_add(self.finish_analysis, code, payload, error, key)
        except Exception as exc:
            GLib.idle_add(self.finish_analysis, 1, {}, str(exc), key)
        finally:
            self.process = None
''',
    '''    def run_analysis(self, command, key):
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            self.process = process
            stdout, stderr = process.communicate()
            code = process.returncode
            payload = json.loads(stdout) if code == 0 else {}
            error = (stderr.strip() or stdout.strip()) if code else ""
            GLib.idle_add(self.finish_analysis, code, payload, error, key)
        except Exception as exc:
            GLib.idle_add(self.finish_analysis, 1, {}, str(exc), key)
        finally:
            if self.process is process:
                self.process = None
''',
)

replace_once(
    "gui/rufusarm64_persistence.py",
    '''    def run_create(self, command):
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            for raw in self.process.stdout or ():
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                else:
                    GLib.idle_add(self.handle_event, event)
            code = self.process.wait()
            GLib.idle_add(self.finish_create, code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Persistent USB creation failed: {exc}")
            GLib.idle_add(self.finish_create, 1)
        finally:
            self.process = None
''',
    '''    def run_create(self, command):
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            self.process = process
            for raw in process.stdout or ():
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                else:
                    GLib.idle_add(self.handle_event, event)
            code = process.wait()
            GLib.idle_add(self.finish_create, code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Persistent USB creation failed: {exc}")
            GLib.idle_add(self.finish_create, 1)
        finally:
            if self.process is process:
                self.process = None
''',
)

path = Path("gui/test_source_structure.py")
text = path.read_text(encoding="utf-8")
marker = "    def test_audit_commands_and_package_assertions_are_not_duplicated(self):\n"
addition = '''    def test_worker_process_references_are_ownership_guarded(self):
        workers = {
            "rufusarm64.py": ("run_download", "run_persistence_plan", "run_writer"),
            "rufusarm64_persistence.py": ("run_analysis", "run_create"),
        }
        failures = []
        for filename, method_names in workers.items():
            path = GUI_ROOT / filename
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            methods = {
                node.name: ast.get_source_segment(source, node) or ""
                for class_node in tree.body
                if isinstance(class_node, ast.ClassDef)
                for node in class_node.body
                if isinstance(node, ast.FunctionDef)
            }
            for method_name in method_names:
                body = methods.get(method_name, "")
                if not body:
                    failures.append(f"{filename}: missing {method_name}")
                    continue
                for required in ("process = None", "self.process = process", "if self.process is process:"):
                    if required not in body:
                        failures.append(f"{filename}:{method_name} lacks {required!r}")
        main_source = (GUI_ROOT / "rufusarm64.py").read_text(encoding="utf-8")
        main_tree = ast.parse(main_source, filename="rufusarm64.py")
        download_source = next(
            ast.get_source_segment(main_source, node) or ""
            for class_node in main_tree.body
            if isinstance(class_node, ast.ClassDef)
            for node in class_node.body
            if isinstance(node, ast.FunctionDef) and node.name == "run_download"
        )
        if "if self.cancel_requested and process.poll() is None:" not in download_source:
            failures.append("rufusarm64.py:run_download does not honor early cancellation")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

'''
if text.count(marker) != 1:
    raise SystemExit("source-structure insertion marker changed")
path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
