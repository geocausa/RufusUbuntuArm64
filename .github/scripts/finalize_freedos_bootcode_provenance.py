#!/usr/bin/env python3
"""Finalize test, packaging, and documentation integration for FreeDOS boot assets."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected one replacement marker, found {text.count(old)}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


test_file = ROOT / "internal" / "freedos" / "bootassets_test.go"
replace_once(
    test_file,
    'import (\n\t"bytes"\n\t"encoding/binary"\n\t"testing"\n)',
    'import (\n\t"bytes"\n\t"encoding/binary"\n\t"fmt"\n\t"testing"\n)',
)
replace_once(
    test_file,
    't.Run(string(rune(sectorSize)), func(t *testing.T) {',
    't.Run(fmt.Sprintf("sector-%d", sectorSize), func(t *testing.T) {',
)

script = ROOT / "scripts" / "test.sh"
marker = '''PYBOOT

if [[ -f vendor/wimlib/source/wimlib-1.14.5-source.tar.gz ]]; then
'''
addition = '''PYBOOT

python3 scripts/extract-freedos-bootassets.py --check
(
  cd vendor/ms-sys
  sha256sum -c UPSTREAM-SHA256SUMS
)
python3 - <<'PYFREEDOSBOOT'
import hashlib
import json
from pathlib import Path

root = Path("internal/freedos/bootassets")
vendor = Path("vendor/ms-sys")
manifest = json.loads((vendor / "FREEDOS-BOOTASSETS.json").read_text(encoding="utf-8"))
assert manifest["schema"] == 1
assert manifest["rufus_commit"] == "6d8fbf98305ff37eb531c45cbd6ff44563c53917"
path = manifest["rufus_default_path"]
assert path == {
    "active_partition_status": "0x80",
    "backup_boot_region_sector": 6,
    "filesystem": "fat32",
    "mbr_writer": "write_rufus_mbr",
    "partition_scheme": "mbr",
    "partition_type": "0x0c",
    "pbr_writer": "write_fat_32_fd_br",
    "preserve_fat32_bpb_and_fsinfo_fields": True,
    "preserve_mbr_disk_signature_and_partition_table": True,
    "primary_boot_region_sector": 0,
}
expected_names = {
    "rufus-mbr-code.bin",
    "fat32-freedos-pbr-0x0.bin",
    "fat32-freedos-pbr-0x52.bin",
    "fat32-freedos-pbr-0x3f0.bin",
}
assert {entry["name"] for entry in manifest["assets"]} == expected_names
for entry in manifest["assets"]:
    data = (root / entry["name"]).read_bytes()
    source = vendor / entry["source"]
    assert len(data) == entry["size"]
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    assert source.is_file()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["source_sha256"]
PYFREEDOSBOOT

if [[ -f vendor/wimlib/source/wimlib-1.14.5-source.tar.gz ]]; then
'''
replace_once(script, marker, addition)

build = ROOT / "scripts" / "build-deb.sh"
replace_once(
    build,
    '''install -Dm644 "${ROOT_DIR}/docs/persistence-qualification.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/persistence-qualification.md"
''',
    '''install -Dm644 "${ROOT_DIR}/docs/persistence-qualification.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/persistence-qualification.md"
install -Dm644 "${ROOT_DIR}/docs/freedos-feasibility.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/freedos-feasibility.md"
''',
)
replace_once(
    build,
    '''for file in PINNED-UPSTREAM.txt UPSTREAM-SHA256SUMS br.c ntfs.c fat32.c \\
  mbr_win7.h br_ntfs_0x0.h br_ntfs_0x54.h br_fat32_0x0.h \\
  br_fat32pe_0x52.h br_fat32pe_0x3f0.h br_fat32pe_0x1800.h; do
''',
    '''for file in PINNED-UPSTREAM.txt UPSTREAM-SHA256SUMS FREEDOS-BOOTASSETS.json \\
  br.c ntfs.c fat32.c mbr_win7.h mbr_rufus.h br_ntfs_0x0.h br_ntfs_0x54.h \\
  br_fat32_0x0.h br_fat32fd_0x52.h br_fat32fd_0x3f0.h \\
  br_fat32pe_0x52.h br_fat32pe_0x3f0.h br_fat32pe_0x1800.h; do
''',
)
replace_once(
    build,
    '''done
install -Dm755 "${ROOT_DIR}/packaging/rufusarm64" \\
''',
    '''done
install -Dm644 "${ROOT_DIR}/scripts/extract-freedos-bootassets.py" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/ms-sys/extract-freedos-bootassets.py"
install -Dm755 "${ROOT_DIR}/packaging/rufusarm64" \\
''',
)

doc = ROOT / "docs" / "freedos-feasibility.md"
replace_once(
    doc,
    '''## Unresolved gates

Implementation remains blocked until all of these are resolved:

1. **Boot-code provenance.** Identify the exact FreeDOS MBR and FAT partition boot-code fragments used by Rufus, trace them to pinned GPL ms-sys source, extract reproducible binary assets, and add byte-level tests.
2. **Payload provenance.** Extract the minimal files directly from the official FreeDOS 1.4 archive, record individual SHA-256 values, preserve corresponding source and licence material, and prove reproducible extraction.
3. **Kernel configuration.** Rufus sets `FORCELBA` at offset `0x0d` to `0x01`. The implementation must prove this field from FreeDOS source/documentation and reject an unexpected kernel before applying or verifying it.
4. **Filesystem geometry.** Define the exact FAT type, cluster sizing, partition limits, hidden-sector fields, active flag, CHS/LBA compatibility fields, and backup boot-sector behavior.
5. **Structural verification.** Implement an ordinary-file disk-image verifier before any loop-device or physical-media test. It must validate MBR/PBR code, FAT BPB consistency, file entries, file bytes, and boot signatures.
6. **Licensing and maintenance.** Ship notices, corresponding source or a durable source offer as required, upstream archive hashes, extraction tooling, update procedure, and a package-size assessment.
7. **Safety integration.** Reuse the identity, root-disk refusal, lock, cancellation, media-changed reporting, and final readback contracts already established for non-bootable formatting.
''',
    '''## Resolved boot-code provenance checkpoint

The default Rufus 4.15 FreeDOS path is now pinned and reproducible from GPL `ms-sys` source at the reviewed Rufus commit:

- Rufus MBR bootstrap: 440 bytes from `mbr_rufus.h`, written without replacing the disk signature or partition table;
- MBR layout contract: the first partition is active and uses FAT32 LBA type `0x0c`;
- FAT32 prefix: 11 bytes from `br_fat32_0x0.h` at offset `0x00`;
- FreeDOS FAT32 loader: 918 bytes from `br_fat32fd_0x52.h` at offset `0x52`;
- FreeDOS continuation: 528 bytes from `br_fat32fd_0x3f0.h` at offset `0x3f0`;
- both the primary boot region and the backup beginning at logical sector 6 are patched and verified;
- the offline extractor, source hashes, Git blob IDs, binary hashes, BPB-preservation tests, MBR-metadata tests, and tamper tests are committed.

This checkpoint validates byte transformations on ordinary in-memory images only. It does not authorize a device operation or establish that a physical PC will boot.

## Unresolved gates

Implementation remains blocked until all of these are resolved:

1. **Payload provenance.** Extract the minimal files directly from the official FreeDOS 1.4 archive, record individual SHA-256 values, preserve corresponding source and licence material, and prove reproducible extraction.
2. **Kernel configuration.** Rufus sets `FORCELBA` at offset `0x0d` to `0x01`. The implementation must prove this field from FreeDOS source/documentation and reject an unexpected kernel before applying or verifying it.
3. **Filesystem geometry.** Define the exact FAT cluster sizing, partition limits, hidden-sector fields, CHS/LBA compatibility fields, and size boundaries.
4. **Structural verification.** Extend the ordinary-file verifier to validate FAT allocation, root-directory entries, payload placement and bytes, and kernel configuration before any loop-device or physical-media test.
5. **Licensing and maintenance.** Complete the payload notices and corresponding-source offer, extraction/update procedure, and package-size assessment.
6. **Safety integration.** Reuse the identity, root-disk refusal, lock, cancellation, media-changed reporting, and final readback contracts already established for non-bootable formatting.
''',
)
replace_once(
    doc,
    '''It is **not implementation-green** until boot-code provenance, reproducible payload extraction, kernel configuration, and an ordinary-file verifier are complete. Until then there must be no GTK option, destructive command, package dependency, or release commitment for FreeDOS.
''',
    '''It is **not implementation-green** until reproducible payload extraction, kernel configuration proof, complete ordinary-file media verification, licensing, and safety integration are complete. Until then there must be no GTK option, destructive command, runtime package dependency, or release commitment for FreeDOS.
''',
)
