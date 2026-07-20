#!/usr/bin/env python3
"""Apply the reviewed Rufus 4.15 FreeDOS boot-code provenance checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "vendor" / "ms-sys"
ASSET_ROOT = ROOT / "internal" / "freedos" / "bootassets"
RUFUS_COMMIT = "6d8fbf98305ff37eb531c45cbd6ff44563c53917"

SOURCE_FILES = (
    "br.c",
    "fat32.c",
    "inc/br_fat32_0x0.h",
    "inc/br_fat32fd_0x52.h",
    "inc/br_fat32fd_0x3f0.h",
    "inc/mbr_rufus.h",
)

ASSETS = (
    {
        "name": "rufus-mbr-code.bin",
        "source": "mbr_rufus.h",
        "write_offset": 0,
        "role": "Rufus default conventional MBR bootstrap; partition table and disk signature remain outside the array",
    },
    {
        "name": "fat32-freedos-pbr-0x0.bin",
        "source": "br_fat32_0x0.h",
        "write_offset": 0,
        "role": "FAT32 jump/OEM prefix before the BIOS parameter block",
    },
    {
        "name": "fat32-freedos-pbr-0x52.bin",
        "source": "br_fat32fd_0x52.h",
        "write_offset": 0x52,
        "role": "FreeDOS FAT32 loader code after the BIOS parameter block",
    },
    {
        "name": "fat32-freedos-pbr-0x3f0.bin",
        "source": "br_fat32fd_0x3f0.h",
        "write_offset": 0x3F0,
        "role": "FreeDOS FAT32 continuation code after filesystem metadata",
    },
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob(root: Path, path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "hash-object", str(path)], text=True
    ).strip()


def copy_sources(rufus: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for relative in SOURCE_FILES:
        source = rufus / "src" / "ms-sys" / relative
        if not source.is_file():
            raise SystemExit(f"missing pinned Rufus source: {source}")
        destination = VENDOR / source.name
        shutil.copyfile(source, destination)
        result[source.name] = {
            "rufus_path": f"src/ms-sys/{relative}",
            "git_blob_sha1": git_blob(rufus, source),
            "sha256": sha256(source),
        }
    return result


def write_manifest(source_metadata: dict[str, dict[str, object]]) -> None:
    entries = []
    for asset in ASSETS:
        output = ASSET_ROOT / str(asset["name"])
        if not output.is_file():
            raise SystemExit(f"missing generated boot asset: {output}")
        source_name = str(asset["source"])
        entries.append(
            {
                **asset,
                "size": output.stat().st_size,
                "sha256": sha256(output),
                "source_git_blob_sha1": source_metadata[source_name]["git_blob_sha1"],
                "source_sha256": source_metadata[source_name]["sha256"],
                "source_path": source_metadata[source_name]["rufus_path"],
            }
        )

    manifest = {
        "schema": 1,
        "upstream": "https://github.com/pbatard/rufus",
        "rufus_commit": RUFUS_COMMIT,
        "scope": "FreeDOS default MBR/FAT32 path only; no device operation is authorized",
        "rufus_default_path": {
            "partition_scheme": "mbr",
            "filesystem": "fat32",
            "partition_type": "0x0c",
            "active_partition_status": "0x80",
            "mbr_writer": "write_rufus_mbr",
            "pbr_writer": "write_fat_32_fd_br",
            "primary_boot_region_sector": 0,
            "backup_boot_region_sector": 6,
            "preserve_mbr_disk_signature_and_partition_table": True,
            "preserve_fat32_bpb_and_fsinfo_fields": True,
        },
        "assets": entries,
    }
    (VENDOR / "FREEDOS-BOOTASSETS.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_pin_record() -> None:
    (VENDOR / "PINNED-UPSTREAM.txt").write_text(
        "\n".join(
            (
                "Upstream: https://github.com/pbatard/rufus",
                f"Commit: {RUFUS_COMMIT} (Rufus 4.15 build 2396)",
                "Assets: pinned GPL ms-sys Rufus MBR, FreeDOS FAT32 PBR, Windows 7 MBR/NTFS/FAT32 PE boot arrays, and the Rufus UEFI:NTFS image",
                "FreeDOS default path: MBR, active first partition, FAT32 LBA type 0x0c, Rufus MBR, FreeDOS FAT32 PBR at primary and sector-6 backup regions",
                "Licensing: each pinned ms-sys source file carries its GPLv2-or-later notice; Rufus is GPLv3-or-later.",
                "",
            )
        ),
        encoding="utf-8",
    )


def write_checksums() -> None:
    files = sorted(
        path
        for path in VENDOR.iterdir()
        if path.is_file() and path.name != "UPSTREAM-SHA256SUMS"
    )
    lines = [f"{sha256(path)}  ./{path.name}" for path in files]
    (VENDOR / "UPSTREAM-SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rufus-root", required=True, type=Path)
    args = parser.parse_args()
    rufus = args.rufus_root.resolve()
    actual = subprocess.check_output(["git", "-C", str(rufus), "rev-parse", "HEAD"], text=True).strip()
    if actual != RUFUS_COMMIT:
        raise SystemExit(f"unexpected Rufus commit {actual}; expected {RUFUS_COMMIT}")

    VENDOR.mkdir(parents=True, exist_ok=True)
    source_metadata = copy_sources(rufus)
    subprocess.run(["python3", str(ROOT / "scripts" / "extract-freedos-bootassets.py")], check=True)
    write_manifest(source_metadata)
    write_pin_record()
    write_checksums()
    subprocess.run(["python3", str(ROOT / "scripts" / "extract-freedos-bootassets.py"), "--check"], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
