#!/usr/bin/env python3
"""Inspect a PE/COFF UEFI application and emit deterministic provenance JSON."""

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

ARM64_MACHINE = 0xAA64
PE32_PLUS_MAGIC = 0x20B
EFI_APPLICATION_SUBSYSTEM = 10
SECURITY_DIRECTORY_INDEX = 4


def require_range(data, start, length, label):
    if start < 0 or length < 0 or start + length > len(data):
        raise ValueError(f"{label} extends beyond the PE file")


def inspect(path):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("file does not contain an MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE header")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("file does not contain a PE signature")
    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    optional_offset = pe_offset + 24
    require_range(data, optional_offset, optional_size, "optional header")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != PE32_PLUS_MAGIC:
        raise ValueError(f"optional header magic is 0x{magic:04x}, expected PE32+ 0x020b")
    if optional_size < 120:
        raise ValueError("PE32+ optional header is too short")
    subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
    directory_count = struct.unpack_from("<I", data, optional_offset + 108)[0]
    certificate_offset = 0
    certificate_size = 0
    if directory_count > SECURITY_DIRECTORY_INDEX:
        entry_offset = optional_offset + 112 + SECURITY_DIRECTORY_INDEX * 8
        require_range(data, entry_offset, 8, "security directory")
        certificate_offset, certificate_size = struct.unpack_from("<II", data, entry_offset)
        if certificate_size:
            require_range(data, certificate_offset, certificate_size, "Authenticode certificate table")
    if machine != ARM64_MACHINE:
        raise ValueError(f"PE machine is 0x{machine:04x}, expected ARM64 0xaa64")
    if subsystem != EFI_APPLICATION_SUBSYSTEM:
        raise ValueError(f"PE subsystem is {subsystem}, expected EFI application 10")
    digest = hashlib.sha256(data).hexdigest()
    return {
        "filename": Path(path).name,
        "sha256": digest,
        "size": len(data),
        "pe": {
            "machine": machine,
            "machine_name": "ARM64",
            "optional_header_magic": magic,
            "format": "PE32+",
            "subsystem": subsystem,
            "subsystem_name": "EFI application",
            "section_count": section_count,
            "coff_timestamp": timestamp,
            "characteristics": characteristics,
        },
        "authenticode": {
            "present": certificate_size > 0,
            "certificate_table_offset": certificate_offset,
            "certificate_table_size": certificate_size,
        },
        "secure_boot": {
            "compatibility_established": False,
            "statement": (
                "An Authenticode certificate table is present, but firmware trust has not been established."
                if certificate_size
                else "The reproducibly built loader is unsigned and is not claimed to boot with Secure Boot enabled."
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--uefi-md5sum-commit", required=True)
    parser.add_argument("--edk2-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--gcc-version", required=True)
    parser.add_argument("--ld-version", required=True)
    args = parser.parse_args()

    result = {
        "schema": 1,
        "artifact": inspect(args.input),
        "sources": {
            "uefi_md5sum": {
                "repository": "https://github.com/pbatard/uefi-md5sum.git",
                "tag": "v1.2",
                "commit": args.uefi_md5sum_commit,
                "license": "GPL-2.0-or-later",
            },
            "edk2": {
                "repository": "https://github.com/tianocore/edk2.git",
                "tag": "edk2-stable202508.01",
                "commit": args.edk2_commit,
            },
        },
        "build": {
            "architecture": "AARCH64",
            "configuration": "RELEASE",
            "toolchain": "EDK2 GCC",
            "source_date_epoch": args.source_date_epoch,
            "gcc_version": args.gcc_version,
            "ld_version": args.ld_version,
            "command": "build -a AARCH64 -b RELEASE -t GCC -p Md5SumPkg.dsc",
        },
        "chainload_contract": {
            "fallback_loader": "EFI/BOOT/BOOTAA64.EFI",
            "original_loader": "EFI/BOOT/bootaa64_original.efi",
            "manifest": "md5sum.txt",
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
