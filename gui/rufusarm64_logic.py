"""Pure, testable helpers for the RufusArm64 GTK front end."""

import re

SUPPORTED_IMAGE_SUFFIXES = (
    ".iso", ".img", ".raw", ".bin",
    ".zip", ".gz", ".bz2", ".xz", ".lzma", ".zst",
    ".vhd", ".vhdx", ".qcow", ".qcow2", ".vmdk", ".ffu",
)
LOCALE_PATTERN = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
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
    """Return an accurate GUI completion message for the selected job."""
    if verify_requested:
        return "The bootable USB was created and verified successfully. Remove it safely before unplugging it."
    if mode == "windows":
        filesystem_name = "NTFS" if filesystem == "ntfs" else "FAT32" if filesystem == "fat32" else "selected"
        return (
            f"The bootable USB was created successfully. The {filesystem_name} filesystem check passed, "
            "but copied-file verification was skipped. Remove it safely before unplugging it."
        )
    return "The bootable USB was created successfully. Verification was skipped. Remove it safely before unplugging it."


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
    lines.append("Planning is read-only. Persistent USB creation remains experimental and command-line only.")
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
