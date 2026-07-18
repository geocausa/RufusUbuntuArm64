#!/usr/bin/env python3
"""Fail closed when tagged releases drift from the packaged runtime loader contract."""
from pathlib import Path


RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
release_text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

required_release_once = {
    "workflow-dispatch recovery path": "  workflow_dispatch:\n",
    "dispatch version input": "      expected_version:\n",
    "loader job": "  uefi-md5sum-loader:\n",
    "release dependency": "    needs: [wim-engine, uefi-md5sum-loader]\n",
    "loader artifact download": "          name: uefi-md5sum-arm64\n          path: vendor/uefi-md5sum/arm64\n",
    "tag-ref refusal": '          test "${GITHUB_REF_TYPE}" = "tag" || {\n',
    "dispatch-version binding": '            test "${EXPECTED_VERSION}" = "${project_version}" || {\n',
    "explicit release tag": "          tag_name: v${{ steps.version.outputs.version }}\n",
    "deterministic loader source asset": "            dist/RufusArm64-${{ steps.version.outputs.version }}-uefi-md5sum-v1.2-source.tar.gz\n",
    "deterministic loader source checksum asset": "            dist/RufusArm64-${{ steps.version.outputs.version }}-uefi-md5sum-v1.2-source.tar.gz.sha256\n",
    "generated loader source-ZIP exclusion": "'vendor/uefi-md5sum/arm64/*'",
    "unsigned disclosure": "The loader is unsigned and is not claimed Secure Boot compatible.",
}
for description, marker in required_release_once.items():
    count = release_text.count(marker)
    if count != 1:
        raise SystemExit(f"{RELEASE_WORKFLOW}: {description} marker occurred {count} times")

if release_text.count("          name: uefi-md5sum-arm64\n") != 2:
    raise SystemExit("release workflow must upload and download exactly one canonical loader artifact")

release_files = release_text.split("      - uses: softprops/action-gh-release@", 1)
if len(release_files) != 2:
    raise SystemExit("release publication step is missing")
publication = release_files[1]
if "bootaa64.efi" in publication:
    raise SystemExit("the unsigned EFI loader must remain package-private, not a standalone release asset")
if "uefi-md5sum-v1.2-source.tar.gz" not in publication:
    raise SystemExit("corresponding uefi-md5sum source is not published")

TAG_WORKFLOW = Path(".github/workflows/version-tag.yml")
tag_text = TAG_WORKFLOW.read_text(encoding="utf-8")
required_tag_once = {
    "main-only push trigger": "    branches: [main]\n",
    "contents write permission": "  contents: write\n",
    "actions write permission": "  actions: write\n",
    "repository ownership guard": "    if: github.repository == 'geocausa/RufusUbuntuArm64'\n",
    "version synchronization gate": "python3 scripts/check-version-sync.py",
    "release artifact gate": "python3 scripts/check-release-runtime-integrity.py",
    "missing-tag-safe reference lookup": "git/matching-refs/tags/${tag}",
    "exact tag reference argument": '--arg ref "refs/tags/${tag}"',
    "exact tag reference filter": "select(.ref == $ref)",
    "exact tag ref creation": '-f ref="refs/tags/${tag}"',
    "exact release commit binding": '-f sha="${GITHUB_SHA}" >/dev/null',
    "release workflow dispatch": "gh workflow run release.yml",
    "tag-ref dispatch": '--ref "${TAG}"',
    "version-input dispatch": '-f expected_version="${VERSION}"',
}
for description, marker in required_tag_once.items():
    count = tag_text.count(marker)
    if count != 1:
        raise SystemExit(f"{TAG_WORKFLOW}: {description} marker occurred {count} times")

if 'git/ref/tags/${tag}' in tag_text:
    raise SystemExit("canonical tagging must not turn an exact-reference 404 body into tag state")
if "2>/dev/null || true" in tag_text:
    raise SystemExit("canonical tagging must not suppress reference lookup failures")
if "secrets." in tag_text:
    raise SystemExit("canonical tagging must use the repository token, not an undeclared secret or PAT")
if "persist-credentials: true" in tag_text:
    raise SystemExit("canonical tagging must not persist checkout credentials")
if "force" in tag_text.lower():
    raise SystemExit("canonical tagging workflow must never force-move a tag")

print("Tagged-release runtime-integrity and canonical-tag publication contracts are complete.")
