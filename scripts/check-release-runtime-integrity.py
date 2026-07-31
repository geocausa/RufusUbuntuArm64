#!/usr/bin/env python3
"""Fail closed when tagged and published releases drift from their contracts."""
from pathlib import Path


def require_once(path: Path, text: str, markers: dict[str, str]) -> None:
    for description, marker in markers.items():
        count = text.count(marker)
        if count != 1:
            raise SystemExit(f"{path}: {description} marker occurred {count} times")


release_path = Path(".github/workflows/release.yml")
release = release_path.read_text(encoding="utf-8")
require_once(release_path, release, {
    "release workflow name": "name: Release\n",
    "manual dispatch": "  workflow_dispatch:\n",
    "tag refusal": '          test "${GITHUB_REF_TYPE}" = "tag" || {\n',
    "version binding": '          tag_version="${GITHUB_REF_NAME#v}"\n',
    "WIM dependency": "    needs: [wim-engine, uefi-md5sum-loader]\n",
    "trust-mode decision": "      - name: Determine release trust mode\n",
    "inert disabled-channel refusal": "disabled release channel must remain exactly inert and contain no bootstrap root",
    "conditional signed checkout": "        if: steps.trust.outputs.signed == 'true'\n        uses: actions/checkout@",
    "conditional signed gate": "      - name: Require threshold-signed staged asset graph\n        if: steps.trust.outputs.signed == 'true'\n",
    "signed verifier": "          bash scripts/verify-release-publication.sh \\\n",
    "release upload": "      - uses: softprops/action-gh-release@",
    "explicit release tag": "          tag_name: v${{ steps.version.outputs.version }}\n",
    "release notes": "          body_path: docs/release-${{ steps.version.outputs.version }}.md\n",
})
if release.count("          name: uefi-md5sum-arm64\n") != 2:
    raise SystemExit("release workflow must upload and download exactly one canonical loader artifact")
if release.index("      - name: Create corresponding source archives\n") > release.index("      - name: Determine release trust mode\n"):
    raise SystemExit("trust mode must be evaluated only after final assets are created")
if release.index("      - name: Require threshold-signed staged asset graph\n") > release.index("      - uses: softprops/action-gh-release@"):
    raise SystemExit("signed asset verification must complete before release upload")
publication = release.split("      - uses: softprops/action-gh-release@", 1)[1]
if "bootaa64.efi" in publication:
    raise SystemExit("the unsigned EFI loader must remain package-private")


tag_path = Path(".github/workflows/version-tag.yml")
tag = tag_path.read_text(encoding="utf-8")
require_once(tag_path, tag, {
    "main trigger": "    branches: [main]\n",
    "ownership guard": "    if: github.repository == 'geocausa/RufusUbuntuArm64'\n",
    "version gate": "python3 scripts/check-version-sync.py",
    "runtime gate": "python3 scripts/check-release-runtime-integrity.py",
    "inert disabled-channel refusal": "disabled release channel must remain exactly inert and contain no bootstrap root",
    "signed-required output": '            echo "signed_required=${signed_required}"\n',
    "conditional metadata checkout": "        if: steps.version.outputs.signed_required == 'true' && steps.version.outputs.metadata_ready == 'true'\n        uses: actions/checkout@",
    "exact tag creation": '-f ref="refs/tags/${TAG}"',
    "exact commit binding": '-f sha="${GITHUB_SHA}" >/dev/null',
    "release dispatch": "gh workflow run release.yml",
})
for forbidden in ("secrets.", "persist-credentials: true"):
    if forbidden in tag:
        raise SystemExit(f"{tag_path}: forbidden credential marker {forbidden}")
if "force" in tag.lower():
    raise SystemExit("canonical tag workflow must never force-move a tag")


published_path = Path(".github/workflows/release-published.yml")
published = published_path.read_text(encoding="utf-8")
require_once(published_path, published, {
    "workflow-run trigger": "  workflow_run:\n",
    "release workflow binding": "    workflows: [Release]\n",
    "successful release condition": "github.event.workflow_run.conclusion == 'success'",
    "exact tag checkout": "          ref: ${{ env.RELEASE_TAG }}\n",
    "immutable commit export": '          echo "RELEASE_COMMIT=${commit_sha}" >> "${GITHUB_ENV}"\n',
    "trust-mode decision": "      - name: Determine release trust mode\n",
    "conditional metadata checkout": "        if: steps.trust.outputs.signed == 'true'\n        uses: actions/checkout@",
    "published asset validator": '            python3 "${validator}" "${release_json}" "${asset_dir}"\n',
    "conditional signed verification": '            if [[ "${SIGNED_RELEASE}" = "true" ]]; then\n',
    "signed verifier": "              bash scripts/verify-release-publication.sh \\\n",
})
for forbidden in ("contents: write", "actions: write", "secrets.", "persist-credentials: true"):
    if forbidden in published:
        raise SystemExit(f"{published_path}: forbidden mutable credential marker {forbidden}")
for command in ("gh release create", "gh release edit", "gh release upload", "gh release delete"):
    if command in published:
        raise SystemExit(f"{published_path}: post-publication verification must remain read-only")
if published.index('          echo "RELEASE_COMMIT=${commit_sha}" >> "${GITHUB_ENV}"\n') > published.index("      - name: Determine release trust mode\n"):
    raise SystemExit("published verification must bind the immutable commit before evaluating trust mode")
if published.index('            python3 "${validator}" "${release_json}" "${asset_dir}"\n') > published.index('            if [[ "${SIGNED_RELEASE}" = "true" ]]; then\n'):
    raise SystemExit("GitHub asset validation must precede optional signature verification")

contract_path = Path(".github/workflows/release-contract.yml")
contract = contract_path.read_text(encoding="utf-8")
if contract.count("    branches: [main]\n") != 2:
    raise SystemExit("release contracts must run on both main pull requests and main pushes")
for marker in (
    "      - .github/workflows/release-published.yml\n",
    "      - scripts/check-published-release.py\n",
    "      - scripts/verify-release-publication.sh\n",
):
    if contract.count(marker) != 2:
        raise SystemExit(f"{contract_path}: missing paired contract path {marker.strip()}")

print("Tagged, canonical-tag, community-release, and signed-release contracts are complete.")
