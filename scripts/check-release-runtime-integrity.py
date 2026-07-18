#!/usr/bin/env python3
"""Fail closed when tagged releases drift from the packaged runtime loader contract."""

from pathlib import Path


WORKFLOW = Path(".github/workflows/release.yml")
text = WORKFLOW.read_text(encoding="utf-8")

required_once = {
    "loader job": "  uefi-md5sum-loader:\n",
    "release dependency": "    needs: [wim-engine, uefi-md5sum-loader]\n",
    "loader artifact download": "          name: uefi-md5sum-arm64\n          path: vendor/uefi-md5sum/arm64\n",
    "deterministic loader source asset": 'dist/RufusArm64-${{ steps.version.outputs.version }}-uefi-md5sum-v1.2-source.tar.gz',
    "deterministic loader source checksum asset": 'dist/RufusArm64-${{ steps.version.outputs.version }}-uefi-md5sum-v1.2-source.tar.gz.sha256',
    "generated loader source-ZIP exclusion": "'vendor/uefi-md5sum/arm64/*'",
    "unsigned disclosure": "The loader is unsigned and is not claimed Secure Boot compatible.",
}
for description, marker in required_once.items():
    count = text.count(marker)
    if count != 1:
        raise SystemExit(f"{WORKFLOW}: {description} marker occurred {count} times")

if text.count("          name: uefi-md5sum-arm64\n") != 2:
    raise SystemExit("release workflow must upload and download exactly one canonical loader artifact")

release_files = text.split("      - uses: softprops/action-gh-release@", 1)
if len(release_files) != 2:
    raise SystemExit("release publication step is missing")
publication = release_files[1]
if "bootaa64.efi" in publication:
    raise SystemExit("the unsigned EFI loader must remain package-private, not a standalone release asset")

if "uefi-md5sum-v1.2-source.tar.gz" not in publication:
    raise SystemExit("corresponding uefi-md5sum source is not published")

print("Tagged-release runtime-integrity artifact contract is complete.")
