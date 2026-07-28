#!/usr/bin/env python3
"""Apply the reviewed #384 patch once, qualify it, commit it, and remove itself."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path, old, new, label):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{label} changed")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_method(path, start_marker, end_marker, replacement, label):
    text = path.read_text(encoding="utf-8")
    try:
        start = text.index(start_marker)
        end = text.index(end_marker, start)
    except ValueError as exc:
        raise SystemExit(f"{label} boundary changed") from exc
    path.write_text(text[:start] + replacement.rstrip() + text[end:], encoding="utf-8")


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


persistence = ROOT / "gui/rufusarm64_persistence.py"
replace_once(persistence, "import signal\n", "", "persistence signal import")
anchor = """from rufusarm64_persistence_logic import (
    build_analyze_command,
    build_create_command,
    inspect_source_identity,
    normalize_boot_label,
    normalize_persistence_gib,
    normalize_plan,
    technical_plan_summary,
    user_plan_summary,
    completion_checklist,
)

APP_ID ="""
replacement = """from rufusarm64_persistence_logic import (
    build_analyze_command,
    build_create_command,
    inspect_source_identity,
    normalize_boot_label,
    normalize_persistence_gib,
    normalize_plan,
    technical_plan_summary,
    user_plan_summary,
    completion_checklist,
)
from rufusarm64_process import (
    communicate_bounded,
    iter_bounded_utf8_lines,
    schedule_process_group_termination,
    terminate_and_reap,
    terminate_process_group,
)

ANALYSIS_STDOUT_LIMIT = 32 * 1024 * 1024
ANALYSIS_STDERR_LIMIT = 1024 * 1024
CREATE_LINE_LIMIT = 1024 * 1024
CREATE_TOTAL_LIMIT = 64 * 1024 * 1024

APP_ID ="""
replace_once(persistence, anchor, replacement, "persistence process import anchor")

new_analysis = '''    def run_analysis(self, command, key):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            if self.cancel_requested and process.poll() is None:
                schedule_process_group_termination(process, grace_seconds=5)
            stdout, stderr = communicate_bounded(
                process,
                stdout_limit=ANALYSIS_STDOUT_LIMIT,
                stderr_limit=ANALYSIS_STDERR_LIMIT,
                timeout=300,
                terminate=lambda force: terminate_process_group(process, force=force),
                label="persistence analysis helper",
            )
            code = process.returncode
            payload = json.loads(stdout) if code == 0 else {}
            error = (stderr.strip() or stdout.strip()) if code else ""
            GLib.idle_add(self.finish_analysis, code, payload, error, key)
        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self.finish_analysis, 1, {}, str(exc), key)
        finally:
            if self.process is process:
                self.process = None
'''
replace_method(
    persistence,
    "    def run_analysis(self, command, key):",
    "\n    def finish_analysis",
    new_analysis,
    "persistence analysis worker",
)

new_create = '''    def run_create(self, command):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                start_new_session=True,
            )
            self.process = process
            if self.cancel_requested and process.poll() is None:
                schedule_process_group_termination(process, grace_seconds=5)
            for raw in iter_bounded_utf8_lines(
                process.stdout,
                line_limit=CREATE_LINE_LIMIT,
                total_limit=CREATE_TOTAL_LIMIT,
                label="persistence creation helper output",
            ):
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                else:
                    GLib.idle_add(self.handle_event, event)
            process.stdout.close()
            code = process.wait()
            GLib.idle_add(self.finish_create, code)
        except Exception as exc:
            if process is not None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self.append_log, f"Persistent USB creation failed: {exc}")
            GLib.idle_add(self.finish_create, 1)
        finally:
            if self.process is process:
                self.process = None
'''
replace_method(
    persistence,
    "    def run_create(self, command):",
    "\n    def handle_event",
    new_create,
    "persistence creation worker",
)

text = persistence.read_text(encoding="utf-8")
cancel_start = text.index(
    "        if self.process and self.process.poll() is None:",
    text.index("    def cancel(self"),
)
cancel_end = text.index("\n\n    def cleanup_cancel", cancel_start)
new_cancel = '''        if self.process and self.process.poll() is None:
            schedule_process_group_termination(self.process, grace_seconds=5)'''
persistence.write_text(text[:cancel_start] + new_cancel + text[cancel_end:], encoding="utf-8")

build = ROOT / "scripts/build-deb.sh"
old_install = '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_ffu_json.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_ffu_json.py"
'''
new_install = '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_process.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_process.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_ffu_json.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_ffu_json.py"
'''
replace_once(build, old_install, new_install, "package process utility installation")

structure = ROOT / "gui/test_source_structure.py"
old_expected = '''            "rufusarm64_persistence.py": {
                "Window": {
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                },
            },
'''
new_expected = '''            "rufusarm64_persistence.py": {
                "Window": {
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                    "run_analysis": (
                        "start_new_session=True",
                        "communicate_bounded(",
                        "stdout_limit=ANALYSIS_STDOUT_LIMIT",
                        "timeout=300",
                        "terminate_process_group",
                    ),
                    "run_create": (
                        "start_new_session=True",
                        "iter_bounded_utf8_lines(",
                        "line_limit=CREATE_LINE_LIMIT",
                        "terminate_and_reap(process)",
                    ),
                    "cancel": ("schedule_process_group_termination(", "grace_seconds=5"),
                },
            },
'''
replace_once(structure, old_expected, new_expected, "persistence process structure contract")

test_path = ROOT / "gui/test_process_cleanup.py"
new_line_tests = '''    def test_total_limit_is_rejected_and_process_is_reaped(self):
        process = self.start(
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('12345678', flush=True); print('12345678', flush=True); time.sleep(30)"
        )
        with self.assertRaises(OutputLimitError):
            list(iter_bounded_utf8_lines(process.stdout, line_limit=16, total_limit=17))
        terminate_and_reap(process, terminate_timeout=0.1, kill_timeout=2)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)

    def test_non_utf8_line_is_rejected_after_reaping(self):
        process = self.start("import os; os.write(1, b'\\xff\\n')")
        with self.assertRaisesRegex(ValueError, "non-UTF-8"):
            list(iter_bounded_utf8_lines(process.stdout, line_limit=16, total_limit=32))
        self.assertEqual(process.wait(timeout=5), 0)
        process.stdout.close()
        self.assertTrue(process.stdout.closed)
'''
replace_method(
    test_path,
    "    def test_total_limit_and_non_utf8_are_rejected(self):",
    "\n\n\nif __name__",
    new_line_tests,
    "bounded line tests",
)

matrix_test = ROOT / "internal/qualification/interruption_matrix_test.go"
text = matrix_test.read_text(encoding="utf-8")
validation_start = text.index('\t\t\tif !strings.HasSuffix(entry.TestFile, "_test.go") {')
validation_end = text.index('\n\t\tcase "physical-only":', validation_start)
new_validation = '''\t\t\tvar needle string
\t\t\tswitch {
\t\t\tcase strings.HasSuffix(entry.TestFile, "_test.go"):
\t\t\t\tif !strings.HasPrefix(entry.TestName, "Test") {
\t\t\t\t\tfailures = append(failures, fmt.Sprintf("%s Go test_name %q does not start with Test", prefix, entry.TestName))
\t\t\t\t}
\t\t\t\tneedle = "func " + entry.TestName + "("
\t\t\tcase strings.HasSuffix(entry.TestFile, ".py") && strings.HasPrefix(filepath.Base(entry.TestFile), "test_"):
\t\t\t\tif !strings.HasPrefix(entry.TestName, "test_") {
\t\t\t\t\tfailures = append(failures, fmt.Sprintf("%s Python test_name %q does not start with test_", prefix, entry.TestName))
\t\t\t\t}
\t\t\t\tneedle = "def " + entry.TestName + "("
\t\t\tdefault:
\t\t\t\tfailures = append(failures, fmt.Sprintf("%s test_file %s is not a supported Go or Python test file", prefix, entry.TestFile))
\t\t\t}
\t\t\tsource, err := readFile(entry.TestFile)
\t\t\tif err != nil {
\t\t\t\tfailures = append(failures, fmt.Sprintf("%s test file %s cannot be read: %v", prefix, entry.TestFile, err))
\t\t\t\tbreak
\t\t\t}
\t\t\tif needle != "" && !bytes.Contains(source, []byte(needle)) {
\t\t\t\tfailures = append(failures, fmt.Sprintf("%s test %s is not declared in %s", prefix, entry.TestName, entry.TestFile))
\t\t\t}'''
matrix_test.write_text(text[:validation_start] + new_validation + text[validation_end:], encoding="utf-8")

matrix_path = ROOT / "docs/interruption-qualification.json"
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
gap = next(
    (item for item in matrix["residual_software_gaps"] if item.get("id") == "gap-helper-process-cleanup"),
    None,
)
if gap is None:
    raise SystemExit("helper-process residual row changed")
gap["reason"] = (
    "The shared process-group, bounded-capture, line-stream, FFU, and persistence paths are executable, "
    "but primary acquisition/writer and the remaining guarded streaming dialogs still need migration to "
    "the shared utility before this boundary can close."
)
gap["planned_test_kind"] = (
    "migrate remaining GTK workers to the package-owned utility and map each workflow-specific final-evidence contract"
)
rows = [
    {
        "id": "helper-process-group-escalation",
        "boundary": "helper-process-cleanup",
        "component": "package-owned GUI helper process groups",
        "failure_mode": "a helper and descendant ignore SIGTERM after UI cancellation",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_process_cleanup.py",
        "test_name": "test_schedule_escalates_group_when_parent_and_descendant_ignore_sigterm",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Only the owned new-session process group is signalled, SIGKILL escalation terminates an unresponsive descendant, and the parent is reaped.",
    },
    {
        "id": "helper-bounded-capture-reaping",
        "boundary": "helper-process-cleanup",
        "component": "bounded helper stdout and stderr capture",
        "failure_mode": "stdout, stderr, timeout, or UTF-8 evidence bounds are exceeded",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_process_cleanup.py",
        "test_name": "test_stdout_and_stderr_limits_force_owned_group_shutdown",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "The owned group is terminated and reaped, both pipes close, and oversized output can never be accepted as final evidence.",
    },
    {
        "id": "helper-bounded-line-stream",
        "boundary": "helper-process-cleanup",
        "component": "streaming JSON and diagnostic helper output",
        "failure_mode": "one line or the complete stream exceeds reviewed limits or contains non-UTF-8 data",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_process_cleanup.py",
        "test_name": "test_total_limit_is_rejected_and_process_is_reaped",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Oversized records are rejected before JSON or log handling and the helper is forcibly reaped without retaining an open output descriptor.",
    },
    {
        "id": "persistence-helper-bounded-workers",
        "boundary": "helper-process-cleanup",
        "component": "persistent live USB analysis and creation GUI workers",
        "failure_mode": "analysis output is unbounded or creation emits an oversized or non-UTF-8 progress record while cancellation races process startup",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_source_structure.py",
        "test_name": "test_slow_gui_subprocesses_use_workers_and_generation_guards",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Both workers launch owned sessions, analysis uses bounded capture, creation uses bounded line streaming, exceptions reap the group, and cancellation schedules forced escalation.",
    },
    {
        "id": "ffu-helper-bounded-evidence",
        "boundary": "helper-process-cleanup",
        "component": "authenticated FFU review and restore helpers",
        "failure_mode": "evidence or diagnostics exceed bounds, time out, or return non-UTF-8 data",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_ffu_json.py",
        "test_name": "test_timeout",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "The shared bounded capture terminates and reaps the FFU helper before returning an error, so malformed or incomplete evidence cannot become success.",
    },
]
existing = {entry["id"] for entry in matrix["entries"]}
if existing.intersection(row["id"] for row in rows):
    raise SystemExit("helper process executable rows already exist")
physical_index = next(
    (index for index, entry in enumerate(matrix["entries"]) if entry.get("status") == "physical-only"),
    len(matrix["entries"]),
)
matrix["entries"][physical_index:physical_index] = rows
matrix_path.write_text(json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

docs = ROOT / "docs/interruption-crash-consistency.md"
text = docs.read_text(encoding="utf-8")
anchor = "- MBR/GPT persistence metadata failure ordering, ext4 initialization cleanup, and partial boot-tree patch evidence.\n"
addition = anchor + "- owned helper-process SIGTERM/SIGKILL escalation, bounded capture and line streaming, FFU evidence handling, and persistence worker reaping.\n"
replace_once(docs, anchor, addition, "helper process documentation coverage")
old_gap = "The inventory deliberately keeps uncovered software cases visible. A missing general partition/filesystem mutation or helper-process cleanup case may not disappear from review merely because persistence or another component has a similar test."
new_gap = "The inventory deliberately keeps uncovered software cases visible. A missing general partition/filesystem mutation or remaining workflow-specific helper-process cleanup case may not disappear from review merely because persistence, FFU, or another component has a shared utility test."
replace_once(docs, old_gap, new_gap, "helper process documentation residual gap")

changelog = ROOT / "CHANGELOG.md"
anchor = "- Qualified persistence partition and filesystem materialization failures, including GPT backup-first ordering, MBR partial/sync errors, cleanup without false completion, and visible partial boot-patch evidence.\n"
addition = anchor + "- Added package-owned bounded helper-process utilities and migrated FFU capture plus persistence analysis and creation to tested process-group escalation, output limits, pipe closure, and reaping.\n"
replace_once(changelog, anchor, addition, "helper process changelog")

run("git", "rm", "-f", "--ignore-unmatch", ".github/workflows/patch-helper-process-foundation-once.yml", ".github/workflows/patch-helper-process-foundation-v2-once.yml", ".github/workflows/diagnose-helper-process-foundation-once.yml", ".github/stage4-process-once.py", "docs/helper-process-patch-diagnostic.txt")
run("gofmt", "-w", "internal/qualification/interruption_matrix_test.go")
run("python3", "-m", "py_compile", "gui/rufusarm64_process.py", "gui/rufusarm64_ffu_json.py", "gui/rufusarm64_persistence.py", "gui/test_process_cleanup.py", "gui/test_source_structure.py")
run("python3", "-m", "unittest", "gui.test_process_cleanup", "gui.test_ffu_json", "gui.test_source_structure")
run("go", "test", "./internal/qualification")
run("git", "add", "CHANGELOG.md", "docs/interruption-crash-consistency.md", "docs/interruption-qualification.json", "gui/rufusarm64_persistence.py", "gui/test_process_cleanup.py", "gui/test_source_structure.py", "internal/qualification/interruption_matrix_test.go", "scripts/build-deb.sh")
run("git", "config", "user.name", "github-actions[bot]")
run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
run("git", "commit", "-m", "reliability: bound persistence helper process cleanup")
run("git", "push", "--force", "origin", "HEAD:feature/helper-process-cleanup")
