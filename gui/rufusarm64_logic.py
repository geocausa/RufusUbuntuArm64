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
