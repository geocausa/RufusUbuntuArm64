"""GTK lifecycle extension for snapshot-bound filesystem ISO capture."""

import json
import os
import signal
import stat
import subprocess
import threading

import rufusarm64_drive_backup_formats as formats
from rufusarm64_iso_capture import (
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    decode_progress_line,
    normalize_plan,
    normalize_report,
    plan_summary,
    progress_summary,
    report_summary,
)

GLib = formats.GLib

_ISO_PHASE_STATUS = {
    "source_view": "Creating and authenticating a private read-only view of the mounted filesystem.",
    "inventory_source": "Inventorying and hashing the supported source filesystem content.",
    "master": "Mastering the private ISO9660/Joliet/UDF image. Do not disconnect the drive.",
    "revalidate_source": "Rechecking the source filesystem before publication.",
    "validate_mount": "Mounting the private image read-only as UDF for independent validation.",
    "validate_content": "Comparing every supported path, size, type, and content digest.",
    "publish": "Publishing the verified ISO without replacing an existing file.",
}


def install_drive_backup_iso():
    """Layer ISO-specific contracts over the reviewed raw/VHD/VHDX extension."""
    formats._FORMAT_LABELS["iso"] = "Filesystem ISO/UDF (.iso)"
    formats._FORMAT_EXTENSIONS["iso"] = ".iso"
    formats.install_drive_backup_formats()
    dialog_class = formats.backup_dialog.DriveImageBackupDialog
    if getattr(dialog_class, "_backup_iso_installed", False):
        return

    original_refresh_plan = dialog_class.refresh_plan
    original_plan_worker = dialog_class._format_plan_worker
    original_plan_ready = dialog_class._plan_ready
    original_confirmation_changed = dialog_class.confirmation_changed
    original_start_run = dialog_class.start_run
    original_run_worker = dialog_class._format_run_worker
    original_progress_ready = dialog_class._format_progress_ready
    original_run_ready = dialog_class._run_ready

    def iso_selected(dialog):
        return formats._selected_format(dialog) == "iso"

    def refresh_plan(dialog):
        if not iso_selected(dialog):
            return original_refresh_plan(dialog)
        if dialog.running or not dialog.output_path:
            return
        dialog.plan_generation += 1
        generation = dialog.plan_generation
        dialog.plan = None
        dialog.run_button.set_sensitive(False)
        dialog.status.set_text("Inventorying the mounted filesystem and calculating a conservative ISO plan…")
        dialog.plan_label.set_text(
            "Checking exact mounted source, supported path semantics, trusted provider, destination collision, and disk separation…"
        )
        try:
            command = build_dry_run_command(
                dialog.binary,
                dialog.device,
                dialog.identity,
                dialog.output_path,
            )
        except ValueError as exc:
            dialog.status.set_text(str(exc))
            return
        threading.Thread(
            target=dialog._format_plan_worker,
            args=(command, generation, "iso", dialog.output_path),
            daemon=True,
        ).start()

    def format_plan_worker(dialog, command, generation, format_name, output_path):
        if format_name != "iso":
            return original_plan_worker(dialog, command, generation, format_name, output_path)
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Filesystem ISO planning failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["device"]["path"] != dialog.device:
                raise ValueError("ISO plan no longer refers to the selected drive.")
            if payload["identity"] != dialog.identity:
                raise ValueError("ISO plan no longer refers to the selected drive identity.")
            if payload["destination"]["path"] != output_path:
                raise ValueError("ISO plan returned a different destination path.")
            GLib.idle_add(dialog._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(dialog._plan_ready, generation, None, str(exc))

    def plan_ready(dialog, generation, payload, error):
        if not iso_selected(dialog):
            return original_plan_ready(dialog, generation, payload, error)
        if dialog.closed or generation != dialog.plan_generation or dialog.running:
            return False
        if error:
            dialog.plan = None
            dialog.plan_label.set_text("Filesystem ISO plan unavailable.")
            dialog.status.set_text(error)
            dialog.confirm_label.set_text("The exact filesystem confirmation phrase appears after planning.")
        else:
            try:
                dialog.plan = normalize_plan(payload)
                dialog.plan_label.set_text(plan_summary(dialog.plan))
                phrase = confirmation_phrase(dialog.plan)
                dialog.confirm_label.set_text(f"Type exactly: {phrase}")
                dialog.status.set_text(
                    "Review the filesystem-remaster limitations, type the exact phrase, then authenticate."
                )
            except ValueError as exc:
                dialog.plan = None
                dialog.plan_label.set_text("Filesystem ISO plan unavailable.")
                dialog.status.set_text(str(exc))
        dialog.confirmation_changed()
        return False

    def confirmation_changed(dialog, *_):
        if not iso_selected(dialog):
            return original_confirmation_changed(dialog)
        enabled = False
        if dialog.plan and dialog.output_path and not dialog.running:
            try:
                expected = confirmation_phrase(dialog.plan)
                enabled = dialog.confirmation.get_text().strip() == expected and not os.path.lexists(dialog.output_path)
            except ValueError:
                enabled = False
        dialog.run_button.set_sensitive(enabled)

    def start_run(dialog, *_):
        if not iso_selected(dialog):
            return original_start_run(dialog)
        if dialog.running or not dialog.plan or not dialog.output_path:
            return
        try:
            expected = confirmation_phrase(dialog.plan)
            if dialog.confirmation.get_text().strip() != expected:
                raise ValueError("Type the exact filesystem SAVE phrase before authentication.")
            command = build_run_command(
                dialog.pkexec,
                dialog.binary,
                dialog.device,
                dialog.identity,
                dialog.output_path,
                dialog.plan,
            )
        except ValueError as exc:
            dialog.status.set_text(str(exc))
            return
        dialog.run_generation += 1
        generation = dialog.run_generation
        dialog.last_progress_done = 0
        dialog.last_progress_phase = ""
        dialog.progress.set_fraction(0.0)
        dialog.progress.set_text("Waiting for administrator authentication…")
        dialog.result.get_buffer().set_text("Filesystem ISO capture in progress…")
        dialog.set_running(True)
        dialog.status.set_text("Authenticate to create the private read-only source view.")
        threading.Thread(target=dialog._format_run_worker, args=(command, generation), daemon=True).start()

    def format_run_worker(dialog, command, generation):
        planned_format = str((dialog.plan or {}).get("destination", {}).get("format") or "")
        if planned_format != "iso":
            return original_run_worker(dialog, command, generation)
        diagnostics = []
        diagnostics_size = 0
        payload = None
        returncode = 1
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            dialog.process = process
            plan = normalize_plan(dialog.plan)
            source_bytes = int(plan["filesystem_capture"]["source_bytes"])
            required_bytes = int(plan["filesystem_capture"]["required_bytes"])
            last_by_phase = {}
            for line in process.stderr:
                progress = decode_progress_line(line)
                if progress is not None:
                    phase = progress["phase"]
                    if progress["done"] < last_by_phase.get(phase, 0):
                        raise ValueError("Filesystem ISO progress moved backwards within a phase.")
                    if phase == "master":
                        total = progress["total"]
                        if total > required_bytes or (total not in {0, required_bytes} and progress["done"] != total):
                            raise ValueError("Filesystem ISO mastering progress violated the admitted bound.")
                    if phase == "validate_content" and progress["total"] > source_bytes:
                        raise ValueError("Filesystem ISO validation progress exceeded the reviewed content size.")
                    if progress["total"] > required_bytes and phase not in {"validate_content"}:
                        raise ValueError("Filesystem ISO progress exceeded the reviewed destination bound.")
                    last_by_phase[phase] = progress["done"]
                    GLib.idle_add(dialog._format_progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            stdout = process.stdout.read()
            returncode = process.wait()
            dialog.process = None
            if stdout.strip():
                payload = normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Filesystem ISO capture did not return its final report.")
            if payload["source_device"] != dialog.device:
                raise ValueError("Filesystem ISO report refers to a different source disk.")
            if payload["source_mount"] != plan["filesystem_capture"]["source_mount"]:
                raise ValueError("Filesystem ISO report refers to a different source mountpoint.")
            if payload["destination"] != dialog.output_path:
                raise ValueError("Filesystem ISO report refers to a different destination.")
            if payload["status"] == "passed":
                if payload["source_bytes"] != source_bytes or payload["required_bytes"] != required_bytes:
                    raise ValueError("Successful filesystem ISO report does not match the reviewed plan.")
            elif payload["source_bytes"] not in {0, source_bytes} or payload["required_bytes"] not in {0, required_bytes}:
                raise ValueError("Filesystem ISO failure report contains impossible plan evidence.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Filesystem ISO report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(dialog.output_path)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_size != payload["output_bytes"]
                    or info.st_uid != os.getuid()
                ):
                    raise ValueError(
                        "The completed ISO does not match the verified report or desktop user."
                    )
            GLib.idle_add(dialog._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            process = dialog.process
            dialog.process = None
            if process is not None:
                dialog._terminate_and_reap(process)
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(dialog._run_ready, generation, None, detail, returncode)

    def format_progress_ready(dialog, generation, progress):
        if str((dialog.plan or {}).get("destination", {}).get("format") or "") != "iso":
            return original_progress_ready(dialog, generation, progress)
        if dialog.closed or generation != dialog.run_generation or not dialog.running:
            return False
        phase = progress["phase"]
        done = progress["done"]
        if phase != dialog.last_progress_phase:
            dialog.last_progress_phase = phase
            dialog.last_progress_done = 0
        if done < dialog.last_progress_done:
            return False
        dialog.last_progress_done = done
        if progress["total"] == 0:
            dialog.progress.pulse()
        else:
            dialog.progress.set_fraction(min(1.0, done / progress["total"]))
        dialog.progress.set_text(progress_summary(progress))
        dialog.status.set_text(_ISO_PHASE_STATUS.get(phase, "Creating and validating the filesystem ISO."))
        return False

    def run_ready(dialog, generation, payload, diagnostics, returncode):
        if str((dialog.plan or {}).get("destination", {}).get("format") or "") != "iso":
            return original_run_ready(dialog, generation, payload, diagnostics, returncode)
        if dialog.closed or generation != dialog.run_generation:
            return False
        dialog.process = None
        dialog.set_running(False)
        dialog.confirmation.set_text("")
        dialog.completed = True
        if payload is None:
            dialog.progress.set_text("Filesystem ISO could not complete")
            dialog.status.set_text("Filesystem ISO capture could not complete. No final image should be used.")
            dialog.result.get_buffer().set_text(diagnostics)
            dialog.parent_window.append_log("Filesystem ISO capture failed to run:\n" + diagnostics)
        else:
            summary = report_summary(payload, dialog.output_path)
            dialog.status.set_text(summary)
            rendered = json.dumps(payload, indent=2, sort_keys=True)
            if diagnostics:
                rendered += "\n\nDiagnostics:\n" + diagnostics
            dialog.result.get_buffer().set_text(rendered)
            dialog.parent_window.append_log("Filesystem ISO capture result:\n" + rendered)
            if payload["status"] == "passed" and returncode == 0:
                dialog.progress.set_fraction(1.0)
                dialog.progress.set_text("Verified filesystem ISO complete")
                dialog.plan = None
                dialog.choose_button.set_sensitive(False)
            elif payload["status"] == "cancelled":
                dialog.progress.set_text("Cancelled safely")
                dialog.plan = None
            else:
                dialog.progress.set_text("Filesystem ISO failed")
                dialog.plan = None
        dialog.parent_window.refresh_devices()
        return False

    dialog_class.refresh_plan = refresh_plan
    dialog_class._format_plan_worker = format_plan_worker
    dialog_class._plan_ready = plan_ready
    dialog_class.confirmation_changed = confirmation_changed
    dialog_class.start_run = start_run
    dialog_class._format_run_worker = format_run_worker
    dialog_class._format_progress_ready = format_progress_ready
    dialog_class._run_ready = run_ready
    dialog_class._backup_iso_installed = True
