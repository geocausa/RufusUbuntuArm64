"""Pure helpers for the Rufus-style ISO Image versus DD Image mode boundary."""

from rufusarm64_logic import inspect_source_identity, normalize_volume_label


def hybrid_mode_available(info):
    """Return whether inspection exposes a bounded UEFI ISOHybrid choice."""
    if not isinstance(info, dict) or info.get("mode") != "raw":
        return False
    profile = info.get("compatibility_profile")
    if not isinstance(profile, dict):
        return False
    methods = profile.get("boot_methods") or []
    return (
        profile.get("write_path") == "hybrid-direct-write"
        and profile.get("hybrid") is True
        and isinstance(methods, list)
        and "UEFI" in methods
    )


def build_iso_write_command(
    pkexec,
    helper,
    image,
    path,
    identity,
    cancel_path,
    volume_label="RUFUS-LIVE",
):
    """Build the narrow identity-bound privileged ISO Image mode command."""
    values = [
        str(value or "").strip()
        for value in (pkexec, helper, image, path, identity, cancel_path)
    ]
    if not all(values):
        raise ValueError(
            "ISO Image mode requires authentication, an image, a USB identity, and a cancellation channel."
        )
    resolved_image, source_identity = inspect_source_identity(values[2])
    return [
        values[0],
        values[1],
        "--operation",
        "iso",
        "--image",
        resolved_image,
        "--expected-source-identity",
        source_identity,
        "--device",
        values[3],
        "--expected-identity",
        values[4],
        "--volume-label",
        normalize_volume_label(volume_label, "fat32"),
        "--cancel-file",
        values[5],
        "--json-progress",
        "--yes",
    ]
