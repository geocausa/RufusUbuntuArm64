#!/usr/bin/env python3
"""Apply reviewed repository integration for the FreeDOS payload checkpoint."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"expected one integration anchor in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


extractor = ROOT / "scripts" / "extract-freedos-payload.py"
replace_once(extractor, "import hashlib\nimport json\n", "import hashlib\nimport io\nimport json\n")
replace_once(
    extractor,
    '''def sha256(data: bytes) -> str:\n    return hashlib.sha256(data).hexdigest()\n\n\ndef git_blob_sha1(data: bytes) -> str:\n''',
    '''def sha256(data: bytes) -> str:\n    return hashlib.sha256(data).hexdigest()\n\n\ndef sha256_path(path: Path) -> str:\n    digest = hashlib.sha256()\n    with path.open("rb") as handle:\n        for chunk in iter(lambda: handle.read(1024 * 1024), b""):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef git_blob_sha1(data: bytes) -> str:\n''',
)
replace_once(
    extractor,
    '''def validate_source_archive(name: str, data: bytes) -> None:\n    record = FILE_RECORDS[name]\n    with zipfile.ZipFile(Path(os.devnull), "w") if False else tempfile.NamedTemporaryFile() as temporary:\n        temporary.write(data)\n        temporary.flush()\n        with zipfile.ZipFile(temporary.name) as handle:\n            members = handle.namelist()\n''',
    '''def validate_source_archive(name: str, data: bytes) -> None:\n    record = FILE_RECORDS[name]\n    with zipfile.ZipFile(io.BytesIO(data)) as handle:\n        members = handle.namelist()\n''',
)
replace_once(
    extractor,
    '''    validate_payload_pair(loaded["KERNL386.SYS"], loaded["KERNEL.SYS"])\n    if b"GNU General Public License, Version 2" not in loaded["FREECOM.LSM"]:\n''',
    '''    freecom_license_path = METADATA_DIR / "FREECOM-LICENSE"\n    if not freecom_license_path.is_file():\n        raise SystemExit("missing vendor/freedos/metadata/FREECOM-LICENSE")\n    with zipfile.ZipFile(io.BytesIO(loaded["freecom-sources.zip"])) as handle:\n        expected_freecom_license = handle.read("license")\n    if freecom_license_path.read_bytes() != expected_freecom_license:\n        raise SystemExit("FreeCOM licence text differs from the pinned source archive")\n\n    validate_payload_pair(loaded["KERNL386.SYS"], loaded["KERNEL.SYS"])\n    if b"GNU General Public License, Version 2" not in loaded["FREECOM.LSM"]:\n''',
)
replace_once(
    extractor,
    '''    archive_data = archive.read_bytes()\n    if sha256(archive_data) != FULLUSB_SHA256:\n        raise SystemExit("FD14-FullUSB.zip SHA-256 does not match the official release")\n''',
    '''    if sha256_path(archive) != FULLUSB_SHA256:\n        raise SystemExit("FD14-FullUSB.zip SHA-256 does not match the official release")\n''',
)
replace_once(
    extractor,
    '''    for name, data in files.items():\n        path = ROOT / FILE_RECORDS[name]["path"]\n        path.parent.mkdir(parents=True, exist_ok=True)\n        path.write_bytes(data)\n    VENDOR_DIR.mkdir(parents=True, exist_ok=True)\n''',
    '''    for name, data in files.items():\n        path = ROOT / FILE_RECORDS[name]["path"]\n        path.parent.mkdir(parents=True, exist_ok=True)\n        path.write_bytes(data)\n    with zipfile.ZipFile(io.BytesIO(files["freecom-sources.zip"])) as handle:\n        freecom_license = handle.read("license")\n    METADATA_DIR.mkdir(parents=True, exist_ok=True)\n    (METADATA_DIR / "FREECOM-LICENSE").write_bytes(freecom_license)\n    VENDOR_DIR.mkdir(parents=True, exist_ok=True)\n''',
)

script_test = ROOT / "scripts" / "test.sh"
replace_once(
    script_test,
    '''PYFREEDOSBOOT\n\nif [[ -f vendor/wimlib/source/wimlib-1.14.5-source.tar.gz ]]; then\n''',
    '''PYFREEDOSBOOT\n\npython3 scripts/extract-freedos-payload.py --check\npython3 -m py_compile scripts/extract-freedos-payload.py\n\nif [[ -f vendor/wimlib/source/wimlib-1.14.5-source.tar.gz ]]; then\n''',
)

feasibility = ROOT / "docs" / "freedos-feasibility.md"
resolved_payload = '''## Resolved payload and kernel checkpoint\n\nThe official checksum-pinned FullUSB archive is now reproduced through its active FAT32 partition and nested BASE packages:\n\n- `COMMAND.COM` is extracted from `FREECOM.ZIP` and matches the pinned Rufus Git object;\n- `KERNL386.SYS` is extracted from `KERNEL.ZIP` with `FORCELBA` initially `0x00`;\n- `KERNEL.SYS` changes only offset `0x0d` to `0x01` and then matches Rufus exactly;\n- payload sizes, SHA-256 values, package hashes, Git blob IDs, source archives, LSM metadata, and GPLv2 texts are pinned;\n- the committed extractor supports network-free repository checking and deterministic regeneration from a locally supplied official archive;\n- Go validation rejects any altered payload byte and returns only defensive copies.\n\nDetailed records are in `docs/freedos-payload-provenance.md` and `vendor/freedos/PAYLOADS.json`.\n\nThese checkpoints validate ordinary-file transformations only. They do not authorize a device operation or establish that a physical PC will boot.\n\n'''
replace_once(feasibility, "## Unresolved gates\n", resolved_payload + "## Unresolved gates\n")
replace_once(
    feasibility,
    '''Implementation remains blocked until all of these are resolved:\n\n1. **Payload provenance.** Extract the minimal files directly from the official FreeDOS 1.4 archive, record individual SHA-256 values, preserve corresponding source and licence material, and prove reproducible extraction.\n2. **Kernel configuration.** Rufus sets `FORCELBA` at offset `0x0d` to `0x01`. The implementation must prove this field from FreeDOS source/documentation and reject an unexpected kernel before applying or verifying it.\n3. **Filesystem geometry.** Define the exact FAT cluster sizing, partition limits, hidden-sector fields, CHS/LBA compatibility fields, and size boundaries.\n4. **Structural verification.** Extend the ordinary-file verifier to validate FAT allocation, root-directory entries, payload placement and bytes, and kernel configuration before any loop-device or physical-media test.\n5. **Licensing and maintenance.** Complete the payload notices and corresponding-source offer, extraction/update procedure, and package-size assessment.\n6. **Safety integration.** Reuse the identity, root-disk refusal, lock, cancellation, media-changed reporting, and final readback contracts already established for non-bootable formatting.\n''',
    '''Implementation remains blocked until all of these are resolved:\n\n1. **Filesystem geometry.** Define the exact FAT cluster sizing, partition limits, hidden-sector fields, CHS/LBA compatibility fields, and size boundaries.\n2. **Structural verification.** Extend the ordinary-file verifier to validate FAT allocation, root-directory entries, payload placement and bytes, kernel configuration, and all boot regions before any loop-device or physical-media test.\n3. **Release maintenance.** Measure the eventual installed package impact and define the payload update cadence before runtime installation.\n4. **Safety integration.** Reuse the identity, root-disk refusal, lock, cancellation, media-changed reporting, and final readback contracts already established for non-bootable formatting.\n''',
)
replace_once(
    feasibility,
    '''It is **not implementation-green** until reproducible payload extraction, kernel configuration proof, complete ordinary-file media verification, licensing, and safety integration are complete. Until then there must be no GTK option, destructive command, runtime package dependency, or release commitment for FreeDOS.\n''',
    '''It is **not implementation-green** until complete ordinary-file FAT media verification, package planning, and safety integration are complete. Until then there must be no GTK option, destructive command, runtime package dependency, or release commitment for FreeDOS.\n''',
)

no_exposure = ROOT / "internal" / "freedos" / "no_exposure_test.go"
replace_once(
    no_exposure,
    '''\t\tfilepath.Join(root, "docs", "freedos-rufus-bootcode-map.txt"),\n''',
    '''\t\tfilepath.Join(root, "docs", "freedos-rufus-bootcode-map.txt"),\n\t\tfilepath.Join(root, ".github", "workflows", "map-freedos-payload.yml"),\n\t\tfilepath.Join(root, ".github", "workflows", "apply-freedos-payload.yml"),\n\t\tfilepath.Join(root, ".github", "workflows", "verify-freedos-payload.yml"),\n\t\tfilepath.Join(root, ".github", "workflows", "extract-freecom-license.yml"),\n\t\tfilepath.Join(root, ".github", "workflows", "finalize-freedos-payload.yml"),\n\t\tfilepath.Join(root, ".github", "scripts", "finalize_freedos_payload.py"),\n\t\tfilepath.Join(root, "docs", "freedos-payload-map.txt"),\n''',
)
