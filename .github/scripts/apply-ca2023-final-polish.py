#!/usr/bin/env python3
from pathlib import Path

replacements = {
    "internal/windowsmedia/ca2023.go": [
        (
            "the pinned UEFI:NTFS first-stage image is signed through Microsoft UEFI CA 2011 and cannot be represented as CA 2023-only media",
            "the pinned UEFI:NTFS first-stage image carries embedded certificate-chain evidence identifying Microsoft UEFI CA 2011 and cannot be represented as CA 2023-only media",
        ),
        (
            "the ISO has no root bootmgr.efi to replace with the CA 2023-signed bootmgr_EX.efi",
            "the ISO has no root bootmgr.efi to replace with the expected CA 2023 bootmgr_EX.efi",
        ),
    ],
    "gui/rufusarm64_logic.py": [
        (
            "Windows UEFI CA 2023 bootloader replacement currently requires FAT32; NTFS uses a CA 2011-signed UEFI:NTFS first stage.",
            "Windows UEFI CA 2023 bootloader replacement currently requires FAT32; the UEFI:NTFS first stage carries only CA 2011 certificate-chain evidence.",
        ),
    ],
    "gui/rufusarm64.py": [
        (
            "Windows UEFI CA 2023 bootloader replacement currently requires FAT32; NTFS uses the pinned CA 2011-signed UEFI:NTFS first stage.",
            "Windows UEFI CA 2023 bootloader replacement currently requires FAT32; the pinned UEFI:NTFS first stage carries only CA 2011 certificate-chain evidence.",
        ),
        (
            "        self.last_status_key = None\n        self.active_verify_requested = verify_requested\n",
            "        self.last_status_key = None\n        self.last_ca2023_manifest = \"\"\n        self.active_verify_requested = verify_requested\n",
        ),
        (
            "            layout_summary = f\"{display_scheme.upper()} / {display_target.upper()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters\"\n",
            "            display_filesystem = filesystem\n            if filesystem == \"auto\":\n                display_filesystem = str(self.windows_capability_analysis.get(\"default_filesystem\") or \"auto\")\n            layout_summary = f\"{display_scheme.upper()} / {display_target.upper()} / {display_filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters\"\n",
        ),
    ],
}

for filename, changes in replacements.items():
    path = Path(filename)
    text = path.read_text(encoding="utf-8")
    for old, new in changes:
        if new in text:
            continue
        if old not in text:
            raise SystemExit(f"missing final-polish anchor in {filename}: {old[:80]}")
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
