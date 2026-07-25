#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


logic = Path("gui/rufusarm64_logic.py")
text = logic.read_text()
marker = "\n\ndef build_ffu_review_command("
if marker in text:
    raise SystemExit("FFU graphical review helpers already exist")
text += r'''


def _ffu_mapping(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"The FFU review returned an invalid {label}.")
    return value


def _ffu_positive_int(mapping, key, label, allow_zero=False):
    value = mapping.get(key)
    if isinstance(value, bool):
        raise ValueError(f"The FFU review returned an invalid {label}.")
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"The FFU review returned an invalid {label}.") from exc
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"The FFU review returned an invalid {label}.")
    return value


def _ffu_sha256(value, label):
    value = str(value or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"The FFU review returned an invalid {label} SHA-256.")
    return value


def _ffu_absolute_path(value, label, device=False):
    value = str(value or "").strip()
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ValueError(f"The FFU review returned an invalid {label} path.")
    if device and (not value.startswith("/dev/") or value == "/dev/"):
        raise ValueError(f"The FFU review returned an invalid {label} path.")
    return value


def _ffu_required_flag(mapping, key, expected, label):
    if mapping.get(key) is not expected:
        raise ValueError(f"The FFU review returned an unsafe {label} state.")


def _ffu_device_request(device):
    device = _ffu_mapping(device, "selected target")
    path = _ffu_absolute_path(device.get("path"), "target device", device=True)
    identity = _ffu_sha256(device.get("identity"), "target identity")
    size = _ffu_positive_int(device, "size", "target capacity")
    logical = _ffu_positive_int(device, "logical_sector_size", "logical sector size")
    physical = _ffu_positive_int(device, "physical_sector_size", "physical sector size")
    if physical < logical or physical % logical != 0:
        raise ValueError("The selected FFU target reports inconsistent sector geometry.")
    return path, identity, size, logical, physical


def build_ffu_review_command(
    helper,
    image,
    device,
    trust_store,
    trust_metadata_policy,
    publisher_policy,
):
    """Build the unprivileged, read-only authenticated FFU review command."""
    helper = _ffu_absolute_path(helper, "FFU helper")
    image = _ffu_absolute_path(image, "FFU image")
    if not image.lower().endswith(".ffu"):
        raise ValueError("Choose a Full Flash Update (.ffu) image.")
    trust_store = _ffu_absolute_path(trust_store, "FFU trust store")
    trust_metadata_policy = _ffu_absolute_path(
        trust_metadata_policy, "FFU trust-metadata policy"
    )
    publisher_policy = _ffu_absolute_path(publisher_policy, "FFU publisher policy")
    path, identity, size, logical, physical = _ffu_device_request(device)
    return [
        helper,
        "ffu",
        "review",
        "--experimental-ffu",
        "--image",
        image,
        "--device",
        path,
        "--expected-identity",
        identity,
        "--target-size",
        str(size),
        "--logical-sector-size",
        str(logical),
        "--physical-sector-size",
        str(physical),
        "--trust-store",
        trust_store,
        "--trust-metadata-policy",
        trust_metadata_policy,
        "--publisher-policy",
        publisher_policy,
        "--json",
    ]


def normalize_ffu_review(payload):
    """Validate and correlate the complete read-only CLI review evidence."""
    payload = _ffu_mapping(payload, "response")
    if payload.get("execution_attempted") is not False:
        raise ValueError("The FFU review unexpectedly crossed the execution boundary.")
    evaluation_time = str(payload.get("evaluation_time") or "").strip()
    if not RFC3339_UTC_PATTERN.fullmatch(evaluation_time):
        raise ValueError("The FFU review returned an invalid evaluation time.")
    source_path = _ffu_absolute_path(payload.get("source_path"), "source image")
    trust_activation = _ffu_sha256(
        payload.get("trust_activation_sha256"), "trust activation"
    )
    descriptor_digest = _ffu_sha256(
        payload.get("descriptor_plan_sha256"), "descriptor plan"
    )
    source_identity = _ffu_mapping(payload.get("source_identity"), "source identity")
    source_size = _ffu_positive_int(source_identity, "Size", "source identity size")
    for key, label in (("Device", "source device"), ("Inode", "source inode")):
        _ffu_positive_int(source_identity, key, label)
    for key, label in (("ModifiedNS", "source modification time"), ("ChangedNS", "source change time")):
        _ffu_positive_int(source_identity, key, label, allow_zero=True)

    target = _ffu_mapping(payload.get("target_plan"), "target plan")
    full = _ffu_mapping(payload.get("full_flash_plan"), "full-flash plan")
    preflight = _ffu_mapping(payload.get("target_preflight"), "target preflight")

    if target.get("schema") != 1 or target.get("mode") != "ffu-restore":
        raise ValueError("The FFU review returned an unsupported target-plan envelope.")
    if full.get("schema") != 1 or full.get("mode") != "ffu-full-flash-restore":
        raise ValueError("The FFU review returned an unsupported full-flash envelope.")
    if preflight.get("schema") != 1 or preflight.get("mode") != "ffu-full-flash-target-preflight":
        raise ValueError("The FFU review returned an unsupported target-preflight envelope.")

    for mapping, key, expected, label in (
        (target, "destructive", True, "target destructive"),
        (target, "source_integrity_authenticated", True, "source authentication"),
        (target, "target_identity_bound", True, "target identity binding"),
        (target, "target_geometry_bound", True, "target geometry binding"),
        (target, "destination_map_resolved", True, "destination-map resolution"),
        (target, "destination_overlap", False, "destination overlap"),
        (target, "validation_checks_required", False, "partial-update validation"),
        (target, "validation_checks_resolved", False, "premature target validation"),
        (target, "confirmation_required", True, "target confirmation"),
        (target, "execution_supported", False, "target execution"),
        (full, "destructive", True, "full-flash destructive"),
        (full, "full_flash_update_confirmed", True, "full-flash classification"),
        (full, "validation_descriptors_absent", True, "validation-descriptor absence"),
        (full, "validation_checks_resolved", True, "full-flash validation"),
        (full, "confirmation_required", True, "full-flash confirmation"),
        (full, "execution_supported", False, "full-flash execution"),
        (preflight, "destructive", True, "preflight destructive"),
        (preflight, "target_discovery_completed", True, "target discovery"),
        (preflight, "whole_disk_confirmed", True, "whole-disk confirmation"),
        (preflight, "normal_removable_target_confirmed", True, "removable-target confirmation"),
        (preflight, "running_system_disk_excluded", True, "system-disk exclusion"),
        (preflight, "protected_mounts_excluded", True, "protected-mount exclusion"),
        (preflight, "target_identity_revalidated", True, "target identity revalidation"),
        (preflight, "target_capacity_revalidated", True, "target capacity revalidation"),
        (preflight, "target_geometry_revalidated", True, "target geometry revalidation"),
        (preflight, "fixed_disk_override_allowed", False, "fixed-disk override"),
        (preflight, "privileged_open_required", True, "privileged-open requirement"),
        (preflight, "execution_supported", False, "preflight execution"),
    ):
        _ffu_required_flag(mapping, key, expected, label)

    path = _ffu_absolute_path(target.get("device_path"), "target device", device=True)
    expected_identity = _ffu_sha256(
        target.get("expected_target_identity"), "expected target identity"
    )
    size = _ffu_positive_int(target, "target_size_bytes", "target capacity")
    logical = _ffu_positive_int(target, "logical_sector_size_bytes", "logical sector size")
    physical = _ffu_positive_int(target, "physical_sector_size_bytes", "physical sector size")
    mutation = _ffu_positive_int(target, "mutation_bytes", "mutation size")
    if mutation > size or physical < logical or physical % logical != 0:
        raise ValueError("The FFU review returned inconsistent target geometry or mutation scope.")
    if _ffu_positive_int(target, "source_file_size", "source file size") != source_size:
        raise ValueError("The FFU source identity and target plan disagree on source size.")
    if _ffu_positive_int(target, "validation_descriptor_count", "validation descriptor count", allow_zero=True) != 0:
        raise ValueError("The FFU review contains unsupported partial-update validation descriptors.")

    target_digest = _ffu_sha256(target.get("plan_sha256"), "target plan")
    integrity_digest = _ffu_sha256(
        target.get("authenticated_integrity_plan_sha256"), "authenticated integrity"
    )
    if _ffu_sha256(target.get("descriptor_plan_sha256"), "target descriptor plan") != descriptor_digest:
        raise ValueError("The FFU descriptor and target plans disagree.")

    for mapping, label in ((full, "full-flash plan"), (preflight, "target preflight")):
        if _ffu_absolute_path(mapping.get("device_path"), f"{label} target", device=True) != path:
            raise ValueError("The FFU review plans disagree on the target path.")
        if _ffu_sha256(mapping.get("expected_target_identity"), f"{label} identity") != expected_identity:
            raise ValueError("The FFU review plans disagree on the target identity.")
        if _ffu_positive_int(mapping, "target_size_bytes", f"{label} capacity") != size:
            raise ValueError("The FFU review plans disagree on target capacity.")
        if _ffu_positive_int(mapping, "logical_sector_size_bytes", f"{label} logical sector size") != logical:
            raise ValueError("The FFU review plans disagree on logical sector size.")
        if _ffu_positive_int(mapping, "physical_sector_size_bytes", f"{label} physical sector size") != physical:
            raise ValueError("The FFU review plans disagree on physical sector size.")
        if _ffu_positive_int(mapping, "mutation_bytes", f"{label} mutation size") != mutation:
            raise ValueError("The FFU review plans disagree on mutation scope.")

    if _ffu_sha256(full.get("restore_target_plan_sha256"), "full-flash target plan") != target_digest:
        raise ValueError("The full-flash plan does not bind the reviewed target plan.")
    full_digest = _ffu_sha256(full.get("plan_sha256"), "full-flash plan")
    if _ffu_sha256(full.get("descriptor_plan_sha256"), "full-flash descriptor plan") != descriptor_digest:
        raise ValueError("The full-flash and descriptor plans disagree.")
    if _ffu_sha256(full.get("authenticated_integrity_plan_sha256"), "full-flash integrity") != integrity_digest:
        raise ValueError("The full-flash and target plans disagree on source integrity.")
    if _ffu_positive_int(full, "store_update_type", "store update type", allow_zero=True) != 0:
        raise ValueError("The FFU review is not a complete full-flash update.")
    if _ffu_positive_int(full, "validation_descriptor_count", "full-flash validation descriptor count", allow_zero=True) != 0:
        raise ValueError("The FFU full-flash review contains validation descriptors.")

    if _ffu_sha256(preflight.get("restore_target_plan_sha256"), "preflight target plan") != target_digest:
        raise ValueError("The target preflight does not bind the reviewed target plan.")
    if _ffu_sha256(preflight.get("full_flash_validation_plan_sha256"), "preflight full-flash plan") != full_digest:
        raise ValueError("The target preflight does not bind the full-flash plan.")
    if _ffu_sha256(preflight.get("authenticated_integrity_sha256"), "preflight integrity") != integrity_digest:
        raise ValueError("The target preflight does not bind authenticated source integrity.")
    if _ffu_sha256(preflight.get("rediscovered_target_identity"), "rediscovered target identity") != expected_identity:
        raise ValueError("The rediscovered FFU target identity changed.")
    _ffu_sha256(preflight.get("plan_sha256"), "target preflight")
    _ffu_positive_int(preflight, "kernel_device_id", "kernel target identity")
    if not str(preflight.get("major_minor") or "").strip():
        raise ValueError("The FFU target preflight is missing its kernel major:minor identity.")

    mounted = preflight.get("mounted_targets")
    if not isinstance(mounted, list):
        raise ValueError("The FFU target preflight returned invalid mount evidence.")
    normalized_mounts = []
    for item in mounted:
        item = _ffu_mapping(item, "mounted target")
        normalized_mounts.append({
            "device_path": _ffu_absolute_path(item.get("device_path"), "mounted target device", device=True),
            "mountpoint": _ffu_absolute_path(item.get("mountpoint"), "mounted target mountpoint"),
        })
    unmount_required = preflight.get("unmount_required")
    if unmount_required is not bool(normalized_mounts):
        raise ValueError("The FFU target preflight returned inconsistent mount state.")

    phrase = str(payload.get("exact_confirmation_phrase") or "")
    expected_phrase = f"RESTORE AUTHENTICATED FFU TO {path} SIZE {size} BYTES"
    if phrase != expected_phrase or full.get("confirmation_phrase") != phrase:
        raise ValueError("The FFU review returned an inconsistent destructive confirmation phrase.")

    return {
        "evaluation_time": evaluation_time,
        "trust_activation_sha256": trust_activation,
        "source_path": source_path,
        "source_size": source_size,
        "descriptor_plan_sha256": descriptor_digest,
        "target_path": path,
        "target_identity": expected_identity,
        "target_size": size,
        "logical_sector_size": logical,
        "physical_sector_size": physical,
        "mutation_bytes": mutation,
        "vendor": str(preflight.get("vendor") or "").strip(),
        "model": str(preflight.get("model") or "").strip(),
        "transport": str(preflight.get("transport") or "").strip(),
        "mounted_targets": normalized_mounts,
        "unmount_required": unmount_required,
        "exact_confirmation_phrase": phrase,
        "target_plan": dict(target),
        "full_flash_plan": dict(full),
        "target_preflight": dict(preflight),
    }


def ffu_review_summary(payload):
    review = normalize_ffu_review(payload)
    model = " ".join(value for value in (review["vendor"], review["model"]) if value).strip()
    target = review["target_path"] + (f" — {model}" if model else "")
    lines = [
        "Authenticated full-flash FFU review passed.",
        f"Source: {review['source_path']} ({human_bytes(review['source_size'])})",
        f"Target: {target} ({human_bytes(review['target_size'])})",
        f"Sector geometry: {review['logical_sector_size']} logical / {review['physical_sector_size']} physical bytes",
        f"Planned changed bytes: {human_bytes(review['mutation_bytes'])}",
    ]
    if review["unmount_required"]:
        lines.append("The target is still mounted and must be safely unmounted before restoration.")
        for item in review["mounted_targets"]:
            lines.append(f"Mounted: {item['device_path']} at {item['mountpoint']}")
    else:
        lines.append("The target is currently unmounted and eligible for exclusive acquisition.")
    lines.extend([
        "",
        "Exact destructive confirmation phrase:",
        review["exact_confirmation_phrase"],
        "",
        "This review is read-only. It did not open or modify the target.",
    ])
    return "\n".join(lines)
'''
logic.write_text(text)


tests = Path("gui/test_logic.py")
text = tests.read_text()
text = replace_once(
    text,
    "import os\nimport tempfile\nimport unittest\n",
    "import copy\nimport os\nimport tempfile\nimport unittest\n",
    "test imports",
)
text = replace_once(
    text,
    "    build_persistence_analyze_command,\n",
    "    build_ffu_review_command,\n    build_persistence_analyze_command,\n",
    "FFU command import",
)
text = replace_once(
    text,
    "    human_rate,\n",
    "    human_rate,\n    ffu_review_summary,\n",
    "FFU summary import",
)
text = replace_once(
    text,
    "    normalize_filesystem,\n",
    "    normalize_ffu_review,\n    normalize_filesystem,\n",
    "FFU normalization import",
)
fixture = r'''


def valid_ffu_review_payload():
    target_size = 64 * 1024 * 1024
    source_size = 1024 * 1024
    mutation = 2 * 1024 * 1024
    identity = "f" * 64
    descriptor = "b" * 64
    integrity = "c" * 64
    target_digest = "7" * 64
    full_digest = "8" * 64
    phrase = f"RESTORE AUTHENTICATED FFU TO /dev/sdz SIZE {target_size} BYTES"
    target = {
        "schema": 1,
        "mode": "ffu-restore",
        "destructive": True,
        "source_file_size": source_size,
        "authenticated_integrity_plan_sha256": integrity,
        "descriptor_plan_sha256": descriptor,
        "catalog_sha256": "d" * 64,
        "hash_table_sha256": "e" * 64,
        "device_path": "/dev/sdz",
        "expected_target_identity": identity,
        "target_size_bytes": target_size,
        "logical_sector_size_bytes": 512,
        "physical_sector_size_bytes": 4096,
        "store_block_size_bytes": 4096,
        "target_block_count": target_size // 4096,
        "minimum_target_bytes": mutation,
        "write_extent_count": 1,
        "mutation_bytes": mutation,
        "resolved_write_extents": [],
        "validation_descriptor_count": 0,
        "source_integrity_authenticated": True,
        "target_identity_bound": True,
        "target_geometry_bound": True,
        "destination_map_resolved": True,
        "destination_overlap": False,
        "validation_checks_required": False,
        "validation_checks_resolved": False,
        "confirmation_required": True,
        "execution_supported": False,
        "plan_sha256": target_digest,
        "warnings": [],
        "limitations": [],
    }
    full = {
        "schema": 1,
        "mode": "ffu-full-flash-restore",
        "destructive": True,
        "source_file_size": source_size,
        "restore_target_plan_sha256": target_digest,
        "authenticated_integrity_plan_sha256": integrity,
        "descriptor_plan_sha256": descriptor,
        "catalog_sha256": "d" * 64,
        "hash_table_sha256": "e" * 64,
        "device_path": "/dev/sdz",
        "expected_target_identity": identity,
        "target_size_bytes": target_size,
        "logical_sector_size_bytes": 512,
        "physical_sector_size_bytes": 4096,
        "store_block_size_bytes": 4096,
        "target_block_count": target_size // 4096,
        "mutation_bytes": mutation,
        "store_update_type": 0,
        "validation_descriptor_count": 0,
        "full_flash_update_confirmed": True,
        "validation_descriptors_absent": True,
        "validation_checks_resolved": True,
        "confirmation_required": True,
        "confirmation_phrase": phrase,
        "execution_supported": False,
        "plan_sha256": full_digest,
        "warnings": [],
        "limitations": [],
    }
    preflight = {
        "schema": 1,
        "mode": "ffu-full-flash-target-preflight",
        "destructive": True,
        "full_flash_validation_plan_sha256": full_digest,
        "restore_target_plan_sha256": target_digest,
        "authenticated_integrity_sha256": integrity,
        "device_path": "/dev/sdz",
        "expected_target_identity": identity,
        "rediscovered_target_identity": identity,
        "target_size_bytes": target_size,
        "logical_sector_size_bytes": 512,
        "physical_sector_size_bytes": 4096,
        "store_block_size_bytes": 4096,
        "kernel_device_id": 1234,
        "major_minor": "8:240",
        "vendor": "Acme",
        "model": "Disposable",
        "transport": "usb",
        "removable": True,
        "hotplug": True,
        "mutation_bytes": mutation,
        "mounted_targets": [],
        "unmount_required": False,
        "target_discovery_completed": True,
        "whole_disk_confirmed": True,
        "normal_removable_target_confirmed": True,
        "running_system_disk_excluded": True,
        "protected_mounts_excluded": True,
        "target_identity_revalidated": True,
        "target_capacity_revalidated": True,
        "target_geometry_revalidated": True,
        "fixed_disk_override_allowed": False,
        "privileged_open_required": True,
        "execution_supported": False,
        "plan_sha256": "9" * 64,
        "warnings": [],
        "limitations": [],
    }
    return {
        "evaluation_time": "2026-07-25T21:00:00Z",
        "trust_activation_sha256": "a" * 64,
        "source_path": "/images/device.ffu",
        "source_identity": {
            "Device": 1,
            "Inode": 2,
            "Size": source_size,
            "ModifiedNS": 3,
            "ChangedNS": 4,
        },
        "descriptor_plan_sha256": descriptor,
        "target_plan": target,
        "full_flash_plan": full,
        "target_preflight": preflight,
        "exact_confirmation_phrase": phrase,
        "execution_attempted": False,
    }
'''
text = replace_once(text, "\n\nclass LogicTests", fixture + "\n\nclass LogicTests", "FFU fixture")
methods = r'''

    def test_ffu_review_command_is_unprivileged_and_exact(self):
        device = {
            "path": "/dev/sdz",
            "identity": "f" * 64,
            "size": 64 * 1024 * 1024,
            "logical_sector_size": 512,
            "physical_sector_size": 4096,
        }
        command = build_ffu_review_command(
            "/usr/lib/rufusarm64/rufusarm64-helper",
            "/images/device.ffu",
            device,
            "/var/lib/rufusarm64/ffu-trust",
            "/etc/rufusarm64/trust-metadata.json",
            "/etc/rufusarm64/publishers.json",
        )
        self.assertEqual(command[:3], ["/usr/lib/rufusarm64/rufusarm64-helper", "ffu", "review"])
        self.assertIn("--experimental-ffu", command)
        self.assertEqual(command[command.index("--logical-sector-size") + 1], "512")
        self.assertEqual(command[command.index("--physical-sector-size") + 1], "4096")
        self.assertEqual(command[-1], "--json")
        for unsafe in ("pkexec", "restore", "--confirm", "--yes", "--allow-fixed"):
            self.assertNotIn(unsafe, command)

    def test_ffu_review_command_refuses_incomplete_or_ambiguous_inputs(self):
        device = {
            "path": "/dev/sdz", "identity": "f" * 64, "size": 1024,
            "logical_sector_size": 512, "physical_sector_size": 4096,
        }
        with self.assertRaises(ValueError):
            build_ffu_review_command("/helper", "/image.iso", device, "/trust", "/metadata", "/publishers")
        with self.assertRaises(ValueError):
            build_ffu_review_command("/helper", "/image.ffu", {**device, "logical_sector_size": 0}, "/trust", "/metadata", "/publishers")
        with self.assertRaises(ValueError):
            build_ffu_review_command("/helper", "/image.ffu", {**device, "physical_sector_size": 768}, "/trust", "/metadata", "/publishers")
        with self.assertRaises(ValueError):
            build_ffu_review_command("helper", "/image.ffu", device, "/trust", "/metadata", "/publishers")
        with self.assertRaises(ValueError):
            build_ffu_review_command("/helper", "/image.ffu", device, "relative", "/metadata", "/publishers")

    def test_ffu_review_normalization_and_summary(self):
        payload = valid_ffu_review_payload()
        review = normalize_ffu_review(payload)
        self.assertEqual(review["target_path"], "/dev/sdz")
        self.assertEqual(review["logical_sector_size"], 512)
        self.assertFalse(review["unmount_required"])
        summary = ffu_review_summary(payload)
        self.assertIn("Authenticated full-flash FFU review passed", summary)
        self.assertIn("Acme Disposable", summary)
        self.assertIn(payload["exact_confirmation_phrase"], summary)
        self.assertIn("read-only", summary)

    def test_ffu_review_normalization_rejects_cross_plan_substitution(self):
        mutations = []
        payload = valid_ffu_review_payload()
        changed = copy.deepcopy(payload)
        changed["target_preflight"]["rediscovered_target_identity"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["full_flash_plan"]["restore_target_plan_sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["target_preflight"]["logical_sector_size_bytes"] = 4096
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["full_flash_plan"]["confirmation_phrase"] += " "
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["target_plan"]["destination_overlap"] = True
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["execution_attempted"] = True
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    normalize_ffu_review(changed)

    def test_ffu_review_reports_mounts_without_authorizing_unmount(self):
        payload = valid_ffu_review_payload()
        payload["target_preflight"]["mounted_targets"] = [{
            "device_path": "/dev/sdz1",
            "mountpoint": "/media/geoca/FFU",
        }]
        payload["target_preflight"]["unmount_required"] = True
        review = normalize_ffu_review(payload)
        self.assertTrue(review["unmount_required"])
        summary = ffu_review_summary(payload)
        self.assertIn("must be safely unmounted", summary)
        self.assertNotIn("unmounting was performed", summary)
'''
text = replace_once(text, "\n\nif __name__ == \"__main__\":", methods + "\n\nif __name__ == \"__main__\":", "FFU tests")
tests.write_text(text)
