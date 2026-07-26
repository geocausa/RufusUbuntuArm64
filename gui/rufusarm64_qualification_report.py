"""Deterministic, no-replace export for USB qualification reports."""

import json
import os

from rufusarm64_device_qualify import normalize_report


_REPORT_TYPE = "rufusarm64-device-qualification-report"


def qualification_report_document(device, identity, report):
    device = str(device or "").strip()
    identity = str(identity or "").strip()
    if not device.startswith("/dev/"):
        raise ValueError("Qualification report export requires a whole device path under /dev.")
    if not identity:
        raise ValueError("Qualification report export requires the reviewed device identity.")
    return {
        "schema": 1,
        "type": _REPORT_TYPE,
        "device_path": device,
        "device_identity": identity,
        "report": normalize_report(report),
    }


def qualification_report_bytes(device, identity, report):
    document = qualification_report_document(device, identity, report)
    rendered = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return rendered.encode("utf-8")


def save_new_qualification_report(path, device, identity, report):
    """Create and synchronize one new report without replacing any filesystem entry."""
    path = str(path or "")
    if not os.path.isabs(path):
        raise ValueError("Choose an absolute path for the new qualification report.")
    directory, name = os.path.split(path)
    if not name or name in {".", ".."}:
        raise ValueError("Choose a file name for the new qualification report.")

    data = qualification_report_bytes(device, identity, report)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(directory, directory_flags)
    file_fd = None
    created = False
    try:
        file_fd = os.open(name, file_flags, 0o600, dir_fd=directory_fd)
        created = True
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("qualification report write made no progress")
            view = view[written:]
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.fsync(directory_fd)
    except Exception:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(directory_fd)
    return path
