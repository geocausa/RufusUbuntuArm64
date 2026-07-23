#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "docs/upstream-default-contract.json",
    '"note": "Supported UEFI-capable Windows media resolves Automatic to GPT; explicit MBR remains available."',
    '"note": "UEFI-capable media resolves Automatic to GPT; proven BIOS-only x86/x64 media resolves Automatic to MBR."',
)
replace_once(
    "docs/upstream-default-contract.json",
    '"note": "Supported UEFI-capable media resolves Automatic to UEFI; BIOS-only media is tracked by issue 260."',
    '"note": "UEFI-capable media resolves Automatic to UEFI; root bootmgr plus bounded x86/x64 boot.wim metadata resolves BIOS-only media to BIOS."',
)
replace_once(
    "docs/upstream-operation-parity.md",
    '| Windows partition scheme | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image/target | Automatic, image-derived; explicit GPT/MBR retained | Conformant for supported UEFI-capable media after #258 |',
    '| Windows partition scheme | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image/target | Automatic resolves GPT for UEFI media and MBR for proven BIOS-only x86/x64 media; explicit GPT/MBR retained | Conformant after #260 |',
)
replace_once(
    "docs/upstream-operation-parity.md",
    '| Windows target system | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image | Automatic, image-derived; explicit UEFI/BIOS retained | Conformant for supported UEFI-capable media after #258; BIOS-only support tracked by #260 |',
    '| Windows target system | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image | Automatic resolves UEFI from standard fallback loaders and BIOS only from root bootmgr plus bounded x86/x64 boot.wim metadata | Conformant after #260 |',
)
