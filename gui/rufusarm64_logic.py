"""Pure, testable helpers for the RufusArm64 GTK front end."""

import json
import os
import re
import stat
import tempfile

def atomic_write_json(path, payload):
    """Durably replace an owner-only JSON file without following directory links."""
    absolute = os.path.abspath(path)
    directory = os.path.dirname(absolute)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    directory_info = os.lstat(directory)
    if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
        raise OSError("settings directory is not a real directory")
    os.chmod(directory, 0o700)

    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=directory)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, absolute)
        temporary = ""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(directory, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


SUPPORTED_IMAGE_SUFFIXES = (
    ".iso", ".img", ".raw", ".bin",
    ".zip", ".gz", ".bz2", ".xz", ".lzma", ".zst",
    ".vhd", ".vhdx", ".qcow", ".qcow2", ".vmdk", ".ffu",
)
LOCALE_PATTERN = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
RFC3339_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
WINDOWS_TIME_ZONES = {
    "UTC": "UTC",
    "Etc/UTC": "UTC",
    "Etc/GMT": "UTC",
    "Europe/London": "GMT Standard Time",
    "Europe/Dublin": "GMT Standard Time",
    "Europe/Lisbon": "GMT Standard Time",
    "Europe/Paris": "Romance Standard Time",
    "Europe/Madrid": "Romance Standard Time",
    "Europe/Brussels": "Romance Standard Time",
    "Europe/Berlin": "W. Europe Standard Time",
    "Europe/Rome": "W. Europe Standard Time",
    "Europe/Amsterdam": "W. Europe Standard Time",
    "Europe/Vienna": "W. Europe Standard Time",
    "Europe/Zurich": "W. Europe Standard Time",
    "Europe/Warsaw": "Central European Standard Time",
    "Europe/Prague": "Central Europe Standard Time",
    "Europe/Budapest": "Central Europe Standard Time",
    "Europe/Athens": "GTB Standard Time",
    "Europe/Helsinki": "FLE Standard Time",
    "Europe/Kyiv": "FLE Standard Time",
    "Europe/Bucharest": "GTB Standard Time",
    "Europe/Istanbul": "Turkey Standard Time",
    "America/New_York": "Eastern Standard Time",
    "America/Detroit": "Eastern Standard Time",
    "America/Toronto": "Eastern Standard Time",
    "America/Chicago": "Central Standard Time",
    "America/Winnipeg": "Central Standard Time",
    "America/Denver": "Mountain Standard Time",
    "America/Edmonton": "Mountain Standard Time",
    "America/Phoenix": "US Mountain Standard Time",
    "America/Los_Angeles": "Pacific Standard Time",
    "America/Vancouver": "Pacific Standard Time",
    "America/Anchorage": "Alaskan Standard Time",
    "Pacific/Honolulu": "Hawaiian Standard Time",
    "America/Sao_Paulo": "E. South America Standard Time",
    "Asia/Jerusalem": "Israel Standard Time",
    "Asia/Dubai": "Arabian Standard Time",
    "Asia/Kolkata": "India Standard Time",
    "Asia/Bangkok": "SE Asia Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Hong_Kong": "China Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Tokyo": "Tokyo Standard Time",
    "Asia/Seoul": "Korea Standard Time",
    "Australia/Perth": "W. Australia Standard Time",
    "Australia/Adelaide": "Cen. Australia Standard Time",
    "Australia/Sydney": "AUS Eastern Standard Time",
    "Australia/Melbourne": "AUS Eastern Standard Time",
    "Pacific/Auckland": "New Zealand Standard Time",
}

RESERVED_USERS = {
    "administrator",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "helpassistant",
    "krbtgt",
    "local",
    "none",
    "system",
}


def human_bytes(value):
    value = float(value or 0)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "0 B"


def human_rate(value):
    value = float(value or 0)
    return f"{human_bytes(value)}/s" if value > 0 else ""


def human_duration(seconds):
    seconds = max(0, int(round(float(seconds or 0))))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:d}:{seconds:02d}"


def progress_status(stage, done, total, rate=0):
    stage = (stage or "Working").replace("_", " ").title()
    done = max(0, int(done or 0))
    total = max(0, int(total or 0))
    rate = max(0.0, float(rate or 0))
    if total <= 0:
        return stage
    done = min(done, total)
    fraction = done / total
    parts = [f"{stage}: {fraction * 100:.1f}%", f"{human_bytes(done)} of {human_bytes(total)}"]
    if rate > 0:
        parts.append(human_rate(rate))
        remaining = max(0, total - done) / rate
        if remaining >= 1 and done < total:
            parts.append(f"{human_duration(remaining)} remaining")
    return " — ".join(parts)


def supported_image_name(path):
    return bool(path) and str(path).lower().endswith(SUPPORTED_IMAGE_SUFFIXES)


def device_label(device):
    model = " ".join(
        value for value in (device.get("vendor", ""), device.get("model", "")) if value
    ).strip() or "USB drive"
    transport = (device.get("tran") or "unknown").upper()
    return f"{device.get('path')} — {model} — {human_bytes(device.get('size'))} — {transport}"




def success_message(mode, verify_requested, filesystem="auto"):
    """Describe completed software checks without implying a firmware boot guarantee."""
    qualification = (
        "This does not prove firmware boot or Secure Boot acceptance; test the media on the intended computer. "
        "Remove it safely before unplugging it."
    )
    if verify_requested:
        return "USB media creation completed. Copied-data verification passed. " + qualification
    if mode == "windows":
        filesystem_name = "NTFS" if filesystem == "ntfs" else "FAT32" if filesystem == "fat32" else "selected"
        return (
            f"USB media creation completed. The {filesystem_name} filesystem consistency check passed, "
            "but copied-file verification was skipped. " + qualification
        )
    return "USB media creation completed. Copied-data verification was skipped. " + qualification


def validate_local_username(value):
    raw_value = value or ""
    value = raw_value.strip()
    if not value:
        return ""
    if raw_value != value or len(value) > 20 or value.endswith("."):
        raise ValueError(
            "Local account names must be 1–20 characters with no leading/trailing spaces or final period."
        )
    if any(not (char.isalnum() or char in " ._-'") for char in value):
        raise ValueError(
            "Local account names may contain only letters, numbers, spaces, periods, underscores, hyphens, and apostrophes."
        )
    if value.lower() in RESERVED_USERS:
        raise ValueError(f'"{value}" is a reserved Windows account name.')
    return value


def normalize_windows_locale(value):
    value = (value or "").strip()
    if not value or value.upper() in {"C", "POSIX", "C.UTF-8", "C.UTF8"}:
        return ""
    value = value.split("@", 1)[0].split(".", 1)[0].replace("_", "-")
    parts = value.split("-")
    if len(parts) >= 2:
        parts[0] = parts[0].lower()
        parts[1] = parts[1].upper()
        value = "-".join(parts)
    else:
        value = value.lower()
    if not LOCALE_PATTERN.match(value):
        return ""
    return value


def windows_timezone_for_iana(value):
    return WINDOWS_TIME_ZONES.get((value or "").strip(), "")


def validate_windows_timezone(value):
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 64 or not re.match(r"^[A-Za-z0-9 _+().-]+$", value):
        raise ValueError("The detected Windows time-zone name is invalid.")
    return value


def normalize_volume_label(value, filesystem="fat32"):
    filesystem = normalize_filesystem(filesystem)
    label = (value or "RUFUSARM64").strip().upper() or "RUFUSARM64"
    limit = 32 if filesystem == "ntfs" else 11
    if len(label) > limit:
        raise ValueError(f"The {filesystem.upper()} volume label must be {limit} characters or fewer.")
    forbidden = '"*/:<>?\\|'
    if filesystem != "ntfs":
        forbidden += "+,.;=[]"
    if any(ord(char) < 0x20 or ord(char) > 0x7E or char in forbidden for char in label):
        raise ValueError(f"The volume label contains a character that {filesystem.upper()} does not support.")
    return label




def normalize_filesystem(value):
    value = (value or "auto").strip().lower()
    if value not in {"auto", "fat32", "ntfs"}:
        raise ValueError("File system must be Automatic, FAT32, or NTFS.")
    return value

def normalize_partition_scheme(value):
    value = (value or "gpt").strip().lower()
    if value not in {"gpt", "mbr"}:
        raise ValueError("Partition scheme must be GPT or MBR.")
    return value


def normalize_target_system(value):
    value = (value or "uefi").strip().lower()
    aliases = {"legacy": "bios", "legacy-bios": "bios", "bios-csm": "bios"}
    value = aliases.get(value, value)
    if value not in {"uefi", "bios"}:
        raise ValueError("Target system must be UEFI or BIOS/CSM.")
    return value


def normalize_cluster_size(value):
    value = str(value or "auto").strip().lower()
    if value in {"", "auto", "0"}:
        return "auto"
    if value not in {"4096", "8192", "16384", "32768"}:
        raise ValueError("Cluster size must be Automatic, 4 KiB, 8 KiB, 16 KiB, or 32 KiB.")
    return value


CHECKSUM_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
CHECKSUM_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
CHECKSUM_LABELS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}


def build_checksum_command(helper, image):
    helper = str(helper or "").strip()
    image = str(image or "").strip()
    if not helper:
        raise ValueError("The RufusArm64 checksum helper is not installed correctly.")
    if not image:
        raise ValueError("Choose an image before calculating checksums.")
    return [helper, "hash", "--all", "--json", image]


def normalize_checksum_result(payload):
    if not isinstance(payload, dict):
        raise ValueError("The checksum helper returned an invalid response.")
    path = str(payload.get("path") or "").strip()
    try:
        size = int(payload.get("size") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The checksum helper returned an invalid image size.") from exc
    digests = payload.get("digests")
    if not path or not os.path.isabs(path) or size <= 0 or not isinstance(digests, list):
        raise ValueError("The checksum helper response is incomplete.")
    if len(digests) != len(CHECKSUM_ALGORITHMS):
        raise ValueError("The checksum helper did not return the complete algorithm set.")
    normalized = []
    for index, algorithm in enumerate(CHECKSUM_ALGORITHMS):
        item = digests[index]
        if not isinstance(item, dict) or item.get("algorithm") != algorithm:
            raise ValueError("The checksum helper returned algorithms in an unexpected order.")
        value = str(item.get("hex") or "").strip()
        if not re.fullmatch(rf"[0-9a-f]{{{CHECKSUM_LENGTHS[algorithm]}}}", value):
            raise ValueError(f"The checksum helper returned an invalid {CHECKSUM_LABELS[algorithm]} value.")
        normalized.append({"algorithm": algorithm, "hex": value})
    return {"path": path, "size": size, "digests": normalized}


def checksum_summary(payload):
    result = normalize_checksum_result(payload)
    lines = [f"File: {result['path']}", f"Size: {human_bytes(result['size'])}", ""]
    for item in result["digests"]:
        lines.append(f"{CHECKSUM_LABELS[item['algorithm']]}: {item['hex']}")
    lines.extend([
        "",
        "MD5 and SHA-1 are shown only for comparison with legacy published checksums.",
        "Use a trusted signature or authenticated catalog for authenticity decisions.",
    ])
    return "\n".join(lines)


def build_acquisition_channel_list_command(helper, config):
    helper = str(helper or "").strip()
    config = str(config or "").strip()
    if not helper or not config:
        raise ValueError("The built-in acquisition channel is not installed correctly.")
    return [helper, "acquire", "channel", "list", "--config", config, "--json"]


def build_acquisition_channel_download_command(helper, config, image_id, output_directory):
    helper = str(helper or "").strip()
    config = str(config or "").strip()
    image_id = str(image_id or "").strip()
    output_directory = str(output_directory or "").strip()
    if not helper or not config:
        raise ValueError("The built-in acquisition channel is not installed correctly.")
    if not image_id:
        raise ValueError("Choose an image from the verified built-in catalog.")
    if not output_directory:
        raise ValueError("Choose a download folder.")
    return [
        helper, "acquire", "channel", "download",
        "--config", config,
        "--id", image_id,
        "--output", output_directory,
        "--json", "--json-progress",
    ]


def normalize_acquisition_channel(payload):
    if not isinstance(payload, dict):
        raise ValueError("The built-in channel returned an invalid response.")
    images = normalize_acquisition_images(payload.get("images"))
    try:
        root_version = int(payload.get("root_version") or 0)
        catalog_version = int(payload.get("catalog_version") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The built-in channel returned invalid metadata versions.") from exc
    generated = str(payload.get("catalog_generated") or "").strip()
    expires = str(payload.get("catalog_expires") or "").strip()
    key_ids = payload.get("signing_key_ids") or []
    if root_version <= 0 or catalog_version <= 0 or not generated or not expires:
        raise ValueError("The built-in channel response is incomplete.")
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")
    if not isinstance(key_ids, list) or not key_ids or any(not isinstance(value, str) or not digest_pattern.fullmatch(value) for value in key_ids):
        raise ValueError("The built-in channel returned invalid signing key identifiers.")
    catalog_sha256 = str(payload.get("catalog_sha256") or "").strip()
    root_sha256 = str(payload.get("root_sha256") or "").strip()
    root_expires = str(payload.get("root_expires") or "").strip()
    if (
        not digest_pattern.fullmatch(catalog_sha256)
        or not digest_pattern.fullmatch(root_sha256)
        or not RFC3339_UTC_PATTERN.fullmatch(generated)
        or not RFC3339_UTC_PATTERN.fullmatch(expires)
        or not RFC3339_UTC_PATTERN.fullmatch(root_expires)
    ):
        raise ValueError("The built-in channel returned incomplete trust metadata.")
    return {
        "root_version": root_version,
        "root_expires": root_expires,
        "root_sha256": root_sha256,
        "catalog_version": catalog_version,
        "catalog_generated": generated,
        "catalog_expires": expires,
        "catalog_sha256": catalog_sha256,
        "signing_key_ids": key_ids,
        "from_cache": bool(payload.get("from_cache")),
        "images": images,
    }


def build_acquisition_list_command(helper, catalog, signature, public_key):
    values = [str(value or "").strip() for value in (helper, catalog, signature, public_key)]
    if not all(values):
        raise ValueError("Choose a catalog, detached signature, and trusted public key.")
    return [
        values[0], "acquire", "list",
        "--catalog", values[1],
        "--signature", values[2],
        "--public-key", values[3],
        "--json",
    ]


def normalize_acquisition_images(payload):
    if not isinstance(payload, list):
        raise ValueError("The verified catalog did not return an image list.")
    images = []
    seen = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("The verified catalog contains an invalid image entry.")
        image_id = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        architecture = str(item.get("architecture") or "unknown").strip()
        version = str(item.get("version") or "").strip()
        filename = str(item.get("filename") or "").strip()
        try:
            size = int(item.get("size") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("The verified catalog contains an invalid image size.") from exc
        if not image_id or not name or not filename or size <= 0:
            raise ValueError("The verified catalog contains an incomplete image entry.")
        if image_id in seen:
            raise ValueError(f'The verified catalog contains duplicate image id "{image_id}".')
        seen.add(image_id)
        images.append({
            "id": image_id,
            "name": name,
            "architecture": architecture,
            "version": version,
            "filename": filename,
            "size": size,
            "sha256": str(item.get("sha256") or "").strip(),
        })
    if not images:
        raise ValueError("The verified catalog contains no downloadable images.")
    return images


def acquisition_image_label(image):
    version = f" {image.get('version')}" if image.get("version") else ""
    return f"{image.get('name')}{version} — {image.get('architecture', 'unknown')} — {human_bytes(image.get('size'))}"


def build_acquisition_download_command(helper, catalog, signature, public_key, image_id, output_directory):
    command = build_acquisition_list_command(helper, catalog, signature, public_key)[:-1]
    image_id = str(image_id or "").strip()
    output_directory = str(output_directory or "").strip()
    if not image_id:
        raise ValueError("Choose an image from the verified catalog.")
    if not output_directory:
        raise ValueError("Choose a download folder.")
    return [
        command[0], "acquire", "download",
        *command[3:],
        "--id", image_id,
        "--output", output_directory,
        "--json", "--json-progress",
    ]



def inspect_source_identity(path):
    """Return the resolved regular-file path and kernel identity token."""
    path = str(path or "").strip()
    if not path:
        raise ValueError("Choose a Linux image first.")
    resolved = os.path.realpath(os.path.abspath(path))
    try:
        info = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Could not inspect the selected image: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError("The selected image must be a non-empty regular file.")
    fields = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if any(int(value) <= 0 for value in fields[:3]) or any(int(value) < 0 for value in fields[3:]):
        raise ValueError("The selected image does not expose a complete kernel identity.")
    return resolved, ":".join(str(int(value)) for value in fields)


def build_persistence_analyze_command(pkexec, helper, image, source_identity, target_size, persistence_gib, cancel_path):
    values = [str(value or "").strip() for value in (pkexec, helper, image, source_identity, cancel_path)]
    if not all(values):
        raise ValueError("Automatic persistence analysis requires authentication, an identity-bound image, and a cancellation channel.")
    try:
        target_size = int(target_size or 0)
        persistence_gib = int(persistence_gib or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Persistence and target sizes must be whole numbers.") from exc
    if target_size <= 0:
        raise ValueError("The selected USB drive does not report a usable capacity.")
    if persistence_gib < 0:
        raise ValueError("Persistence size cannot be negative.")
    return [
        values[0], values[1], "persistence", "analyze",
        "--image", values[2],
        "--expected-source-identity", values[3],
        "--target-size", str(target_size),
        "--size", f"{persistence_gib}G" if persistence_gib else "0",
        "--cancel-file", values[4],
        "--json",
    ]

def build_persistence_plan_command(helper, image, media_root, target_size, persistence_gib=0):
    helper = str(helper or "").strip()
    image = str(image or "").strip()
    media_root = str(media_root or "").strip()
    try:
        target_size = int(target_size or 0)
        persistence_gib = int(persistence_gib or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Persistence and target sizes must be whole numbers.") from exc
    if not helper or not image or not media_root:
        raise ValueError("Choose an image, its mounted media folder, and a USB drive.")
    if target_size <= 0:
        raise ValueError("The selected USB drive does not report a usable capacity.")
    if persistence_gib < 0:
        raise ValueError("Persistence size cannot be negative.")
    return [
        helper, "persistence", "plan",
        "--image", image,
        "--media-root", media_root,
        "--target-size", str(target_size),
        "--size", f"{persistence_gib}G" if persistence_gib else "0",
        "--json",
    ]


def persistence_plan_summary(payload):
    if not isinstance(payload, dict):
        raise ValueError("The persistence planner returned an invalid response.")
    detection = payload.get("detection")
    plan = payload.get("plan")
    if not isinstance(detection, dict) or not isinstance(plan, dict):
        raise ValueError("The persistence planner response is incomplete.")
    name = str(detection.get("display_name") or detection.get("DisplayName") or detection.get("family") or "Linux media")
    family = str(detection.get("family") or detection.get("Family") or "unknown")
    filesystem = str(plan.get("filesystem") or plan.get("Filesystem") or "ext4")
    label = str(plan.get("filesystem_label") or plan.get("FilesystemLabel") or "")
    parameter = str(plan.get("boot_parameter") or plan.get("BootParameter") or "")
    size = int(plan.get("size_bytes") or plan.get("SizeBytes") or 0)
    patch_paths = plan.get("patch_paths") or plan.get("PatchPaths") or []
    if not isinstance(patch_paths, list):
        patch_paths = []
    lines = [
        f"Compatible media: {name}",
        f"Persistence family: {family}",
        f"Planned partition: {filesystem} {human_bytes(size)}" + (f' labelled "{label}"' if label else ""),
    ]
    if parameter:
        lines.append(f"Boot parameter: {parameter}")
    if patch_paths:
        lines.append("Boot files to update: " + ", ".join(str(path) for path in patch_paths))
    lines.append("Planning is read-only. Use the guarded persistent USB creator for the destructive creation step.")
    return "\n".join(lines)


UEFI_ARCHITECTURES = {
    "native",
    "386",
    "amd64",
    "arm",
    "arm64",
    "riscv64",
    "loongarch64",
}


def normalize_uefi_architecture(value):
    value = str(value or "native").strip().lower()
    aliases = {
        "": "native",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "x64": "amd64",
        "i386": "386",
        "i686": "386",
        "loong64": "loongarch64",
    }
    value = aliases.get(value, value)
    if value not in UEFI_ARCHITECTURES:
        raise ValueError("Choose Native, x86, x86-64, ARM, ARM64, RISC-V 64, or LoongArch 64.")
    return value


def build_uefi_validate_command(
    helper,
    directory,
    architecture="native",
    max_files=512,
    require_fallback=True,
    dbx_file="",
    firmware=False,
    sbat_level_file="",
    firmware_sbat=False,
):
    helper = str(helper or "").strip()
    directory = str(directory or "").strip()
    dbx_file = str(dbx_file or "").strip()
    sbat_level_file = str(sbat_level_file or "").strip()
    if not helper:
        raise ValueError("The RufusArm64 validation helper is not installed correctly.")
    if not directory:
        raise ValueError("Choose a mounted or extracted UEFI media folder.")
    try:
        max_files = int(max_files)
    except (TypeError, ValueError) as exc:
        raise ValueError("The EFI file limit must be a whole number.") from exc
    if max_files <= 0 or max_files > 4096:
        raise ValueError("The EFI file limit must be between 1 and 4096.")
    if dbx_file and firmware:
        raise ValueError("Choose either a local DBX file or the running firmware DBX, not both.")
    if sbat_level_file and firmware_sbat:
        raise ValueError("Choose either a local SBAT level or the running firmware SBAT level, not both.")
    command = [
        helper,
        "uefi",
        "validate",
        "--directory",
        directory,
        "--arch",
        normalize_uefi_architecture(architecture),
        "--max-files",
        str(max_files),
        f"--require-fallback={'true' if require_fallback else 'false'}",
    ]
    if dbx_file:
        command.extend(["--dbx", dbx_file])
    elif firmware:
        command.append("--firmware")
    if sbat_level_file:
        command.extend(["--sbat-level", sbat_level_file])
    elif firmware_sbat:
        command.append("--firmware-sbat")
    command.append("--json")
    return command


def normalize_uefi_validation(payload):
    if not isinstance(payload, dict):
        raise ValueError("The UEFI validator returned an invalid response.")
    root = str(payload.get("root") or "").strip()
    architecture = str(payload.get("architecture") or "").strip()
    fallback_path = str(payload.get("fallback_path") or "").strip()
    files = payload.get("files")
    warnings = payload.get("warnings") or []
    errors = payload.get("errors") or []
    if not root or not architecture or not fallback_path or not isinstance(files, list):
        raise ValueError("The UEFI validator response is incomplete.")
    if not isinstance(warnings, list) or not isinstance(errors, list):
        raise ValueError("The UEFI validator returned invalid warning or error lists.")
    normalized_files = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("The UEFI validator returned an invalid file result.")
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError("The UEFI validator returned a file result without a path.")
        file_warnings = item.get("warnings") or []
        if not isinstance(file_warnings, list):
            raise ValueError("The UEFI validator returned invalid per-file warnings.")
        try:
            sbat_count = len(item.get("sbat") or [])
            certificates = int(item.get("embedded_certificates") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("The UEFI validator returned invalid per-file metadata.") from exc
        normalized_files.append({
            "path": path,
            "machine_name": str(item.get("machine_name") or "unknown"),
            "subsystem_name": str(item.get("subsystem_name") or "unknown subsystem"),
            "fallback": bool(item.get("fallback")),
            "direct_hash_revoked": bool(item.get("direct_hash_revoked")),
            "x509_certificate_revoked": bool(item.get("x509_certificate_revoked")),
            "sbat_revoked": bool(item.get("sbat_revoked")),
            "sbat_revocations": list(item.get("sbat_revocations") or []),
            "embedded_certificates": max(0, certificates),
            "sbat_records": sbat_count,
            "warnings": [str(value) for value in file_warnings],
            "error": str(item.get("error") or "").strip(),
        })
    return {
        "root": root,
        "architecture": architecture,
        "fallback_path": fallback_path,
        "fallback_found": bool(payload.get("fallback_found")),
        "dbx_checked": bool(payload.get("dbx_checked")),
        "sbat_level_checked": bool(payload.get("sbat_level_checked")),
        "sbat_level_source": str(payload.get("sbat_level_source") or "").strip(),
        "sbat_level_datestamp": str(payload.get("sbat_level_datestamp") or "").strip(),
        "sbat_revoked": bool(payload.get("sbat_revoked")),
        "valid": bool(payload.get("valid")),
        "revoked": bool(payload.get("revoked")),
        "files": normalized_files,
        "warnings": [str(value) for value in warnings],
        "errors": [str(value) for value in errors],
        "raw": payload,
    }


def uefi_validation_summary(payload):
    result = normalize_uefi_validation(payload)
    state = "Validation passed" if result["valid"] else "Validation found problems"
    lines = [
        f"{state}: {result['architecture']} UEFI media",
        f"Media root: {result['root']}",
        f"Fallback loader: {result['fallback_path']} ({'found' if result['fallback_found'] else 'missing'})",
        f"DBX revocations checked: {'yes' if result['dbx_checked'] else 'no'}",
        f"SBAT level checked: {'yes' if result['sbat_level_checked'] else 'no'}",
        f"EFI executables checked: {len(result['files'])}",
    ]
    if result["sbat_level_checked"]:
        lines.append(
            f"SBAT source: {result['sbat_level_source']}"
            + (f" (datestamp {result['sbat_level_datestamp']})" if result['sbat_level_datestamp'] else "")
        )
    for item in result["files"]:
        status = "OK"
        if item["direct_hash_revoked"] or item["x509_certificate_revoked"] or item["sbat_revoked"]:
            status = "REVOKED"
        elif item["error"]:
            status = "ERROR"
        elif item["warnings"]:
            status = "WARNING"
        fallback = " fallback" if item["fallback"] else ""
        lines.append(
            f"{status}: {item['path']}{fallback} — {item['machine_name']}; "
            f"{item['subsystem_name']}; SBAT records {item['sbat_records']}"
        )
        for revocation in item["sbat_revocations"]:
            if isinstance(revocation, dict):
                lines.append(
                    "  SBAT revoked: "
                    f"{revocation.get('component', 'unknown')} generation "
                    f"{revocation.get('image_generation', '?')} is below trusted minimum "
                    f"{revocation.get('minimum_generation', '?')}"
                )
        for warning in item["warnings"]:
            lines.append(f"  Warning: {warning}")
        if item["error"]:
            lines.append(f"  Error: {item['error']}")
    for warning in result["warnings"]:
        lines.append(f"Warning: {warning}")
    for error in result["errors"]:
        lines.append(f"Error: {error}")
    lines.append("This read-only check does not prove that the intended computer will boot the media.")
    return "\n".join(lines)

def build_writer_command(
    pkexec,
    helper,
    image,
    path,
    identity,
    verify,
    cancel_path,
    volume_label="RUFUSARM64",
    windows_options=None,
    partition_scheme="gpt",
    target_system="uefi",
    filesystem="auto",
    cluster_size="auto",
    driver_folder="",
    dbx_file="",
    quick_format=True,
    bad_block_check=False,
):
    if not identity:
        raise ValueError("missing device identity")
    options = dict(windows_options or {})
    partition_scheme = normalize_partition_scheme(partition_scheme)
    target_system = normalize_target_system(target_system)
    if target_system == "bios" and partition_scheme != "mbr":
        raise ValueError("BIOS/CSM requires the MBR partition scheme.")
    command = [
        pkexec,
        helper,
        "write",
        "--image",
        image,
        "--device",
        path,
        "--mode",
        "auto",
        "--yes",
        "--json-progress",
        "--expected-identity",
        identity,
        "--cancel-file",
        cancel_path,
        "--volume-label",
        normalize_volume_label(volume_label, filesystem),
        "--partition-scheme",
        partition_scheme,
        "--target-system",
        target_system,
        "--filesystem",
        normalize_filesystem(filesystem),
        "--cluster-size",
        normalize_cluster_size(cluster_size),
    ]
    if driver_folder:
        command.extend(["--driver-folder", str(driver_folder)])
    if dbx_file:
        command.extend(["--dbx-file", str(dbx_file)])
    if not quick_format:
        command.append("--full-format")
    if bad_block_check:
        command.append("--bad-block-check")
    if verify:
        command.append("--verify")
    if options.get("bypass_hardware"):
        command.append("--win-bypass-hardware")
    if options.get("bypass_online_account"):
        command.append("--win-bypass-online-account")
    local_user = validate_local_username(options.get("local_user", ""))
    if local_user:
        command.extend(["--win-local-user", local_user])
    if options.get("reduce_data_collection"):
        command.append("--win-reduce-data-collection")
    if options.get("disable_bitlocker"):
        command.append("--win-disable-bitlocker")
    if options.get("use_regional_settings"):
        locale_value = normalize_windows_locale(options.get("locale", ""))
        timezone_value = validate_windows_timezone(options.get("timezone", ""))
        if locale_value:
            command.extend(["--win-locale", locale_value])
        if timezone_value:
            command.extend(["--win-timezone", timezone_value])
    return command
