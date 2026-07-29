#!/usr/bin/env python3
"""Deterministically move Windows UEFI:NTFS handling to the shared package."""

from pathlib import Path


SOURCE = Path("internal/windowsmedia/windowsmedia.go")
CHANGELOG = Path("CHANGELOG.md")
IMPORT = '\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n'
IMPORT_ANCHOR = '\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n'
OLD_CHANGELOG = """- Expanded Linux ISO Image mode with exact MBR/GPT selection, reviewed FAT32 cluster sizes, an editable per-ISO label that resets when the image changes, and option-bound confirmation, diagnostics, GPT metadata readback, and real reopened-loop qualification.
- Kept UEFI and FAT32 capability-bound and kept DD Image mode immutable; Linux NTFS/UEFI:NTFS extraction and broader filesystem/target-system parity remain planned.
"""
NEW_CHANGELOG = """- Expanded Linux ISO Image mode with Automatic/FAT32/NTFS selection, reviewed MBR/GPT and 4/8/16/32 KiB cluster choices, filesystem-specific labels, and exact option binding through confirmation, the privileged helper, diagnostics, and result evidence.
- Added a shared pinned UEFI:NTFS implementation for Windows and Linux media, guarded NTFS path-policy inspection, complete copied-file and boot-partition readback, and detached-and-reopened MBR/GPT FAT32/NTFS loop qualification while keeping DD Image mode immutable. BIOS/dual-mode Linux extraction, NTFS persistence, and physical firmware boot remain separately bounded.
"""


def replace_function(text: str, start_marker: str, next_marker: str, replacement: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        if replacement.strip() in text:
            return text
        raise SystemExit(f"missing function marker: {start_marker}")
    end = text.find(next_marker, start)
    if end < 0:
        raise SystemExit(f"missing next function marker: {next_marker}")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:]


def update_source() -> None:
    text = SOURCE.read_text(encoding="utf-8")

    if IMPORT not in text:
        if IMPORT_ANCHOR not in text:
            raise SystemExit("missing windowsmedia import anchor")
        text = text.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT, 1)

    old_constants = (
        '\tbundledUEFINTFSPath   = "/usr/lib/rufusarm64/uefi-ntfs.img"\n'
        '\tuefiNTFSImageSHA256   = "72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e"\n'
    )
    new_constants = (
        '\tbundledUEFINTFSPath   = uefintfs.BundledImage\n'
        '\tuefiNTFSImageSHA256   = uefintfs.ImageSHA256\n'
    )
    if old_constants in text:
        text = text.replace(old_constants, new_constants, 1)
    elif new_constants not in text:
        raise SystemExit("missing Windows UEFI:NTFS constants")

    text = replace_function(
        text,
        "func uefiNTFSImageFile() (string, uint64, error) {",
        "func writeUEFINTFSPartitionImage",
        '''func uefiNTFSImageFile() (string, uint64, error) {
\tasset, err := uefintfs.Locate()
\tif err != nil {
\t\treturn "", 0, err
\t}
\treturn asset.Path(), asset.Size(), nil
}''',
    )
    text = replace_function(
        text,
        "func writeUEFINTFSPartitionImage(target *os.File, imagePath string, layout partitionLayout) error {",
        "func verifyUEFINTFSPartition",
        '''func writeUEFINTFSPartitionImage(target *os.File, imagePath string, layout partitionLayout) error {
\tasset, err := uefintfs.Open(imagePath)
\tif err != nil {
\t\treturn fmt.Errorf("reverify UEFI:NTFS image before writing: %w", err)
\t}
\treturn uefintfs.WriteAndVerify(target, asset, uefintfs.Partition{
\t\tStartBytes: layout.PartitionStartBytes,
\t\tSizeBytes:  layout.PartitionSizeBytes,
\t})
}''',
    )
    text = replace_function(
        text,
        "func verifyUEFINTFSPartition(partitionPath, imagePath string) error {",
        "func verifyDirectory",
        '''func verifyUEFINTFSPartition(partitionPath, imagePath string) error {
\t// Hermetic integration tests use a regular file as a synthetic partition
\t// node. The whole-disk writer has already performed exact shared readback.
\tif info, err := os.Stat(partitionPath); err == nil && info.Mode().IsRegular() {
\t\treturn nil
\t}
\tasset, err := uefintfs.Open(imagePath)
\tif err != nil {
\t\treturn fmt.Errorf("reverify UEFI:NTFS image before partition comparison: %w", err)
\t}
\treturn uefintfs.VerifyPartitionPath(partitionPath, asset)
}''',
    )

    required = (
        'bundledUEFINTFSPath   = uefintfs.BundledImage',
        'uefiNTFSImageSHA256   = uefintfs.ImageSHA256',
        'asset, err := uefintfs.Locate()',
        'return uefintfs.WriteAndVerify',
        'return uefintfs.VerifyPartitionPath',
    )
    for marker in required:
        if marker not in text:
            raise SystemExit(f"shared UEFI:NTFS transformation incomplete: {marker}")

    SOURCE.write_text(text, encoding="utf-8")


def update_changelog() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    if OLD_CHANGELOG in text:
        text = text.replace(OLD_CHANGELOG, NEW_CHANGELOG, 1)
    elif NEW_CHANGELOG not in text:
        raise SystemExit("missing Unreleased ISO Image mode changelog block")
    CHANGELOG.write_text(text, encoding="utf-8")


def main() -> None:
    update_source()
    update_changelog()


if __name__ == "__main__":
    main()
