#!/usr/bin/env python3
"""Fail closed when tagged and published releases drift from their contracts."""
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
    "missing-tag-safe lookup": 'git/matching-refs/tags/${tag}',
    "exact matching tag filter": 'select(.ref == \\"refs/tags/${tag}\\")',
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
    raise SystemExit("canonical tag lookup must not treat a 404 response body as an existing ref")
if "secrets." in tag_text:
    raise SystemExit("canonical tagging must use the repository token, not an undeclared secret or PAT")
if "persist-credentials: true" in tag_text:
    raise SystemExit("canonical tagging must not persist checkout credentials")
if "force" in tag_text.lower():
    raise SystemExit("canonical tagging workflow must never force-move a tag")

PUBLISHED_WORKFLOW = Path(".github/workflows/release-published.yml")
published_text = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
required_published_once = {
    "published-release trigger": "    types: [published]\n",
    "manual recovery dispatch": "  workflow_dispatch:\n",
    "manual tag input": "      tag:\n",
    "contents read permission": "  contents: read\n",
    "repository ownership guard": "    if: github.repository == 'geocausa/RufusUbuntuArm64'\n",
    "event-or-input tag binding": "      RELEASE_TAG: ${{ github.event.release.tag_name || inputs.tag }}\n",
    "exact tag checkout": "          ref: ${{ env.RELEASE_TAG }}\n",
    "annotated tag resolution": '              tag_json="$(gh api "/repos/${GITHUB_REPOSITORY}/git/tags/${ref_sha}")"\n',
    "annotated tag commit requirement": '              test "${target_type}" = "commit" || {\n',
    "checked-out SHA binding": '          test "$(git rev-parse HEAD)" = "${commit_sha}" || {\n',
    "release metadata query": '          gh release view "${RELEASE_TAG}" \\\n',
    "release asset download": '          gh release download "${RELEASE_TAG}" \\\n',
    "published asset validator": '          python3 scripts/check-published-release.py "${release_json}" "${asset_dir}"\n',
}
for description, marker in required_published_once.items():
    count = published_text.count(marker)
    if count != 1:
        raise SystemExit(f"{PUBLISHED_WORKFLOW}: {description} marker occurred {count} times")

for forbidden in ("contents: write", "actions: write", "secrets.", "persist-credentials: true"):
    if forbidden in published_text:
        raise SystemExit(f"{PUBLISHED_WORKFLOW}: forbidden mutable credential marker: {forbidden}")
for forbidden_command in ("gh release create", "gh release edit", "gh release upload", "gh release delete"):
    if forbidden_command in published_text:
        raise SystemExit(f"{PUBLISHED_WORKFLOW}: published-release verification must remain read-only")

CONTRACT_WORKFLOW = Path(".github/workflows/release-contract.yml")
contract_text = CONTRACT_WORKFLOW.read_text(encoding="utf-8")
if contract_text.count("    branches: [main]\n") != 2:
    raise SystemExit("release contracts must run on both main pull requests and main pushes")
required_contract_once = {
    "manual contract dispatch": "  workflow_dispatch:\n",
    "published workflow path": "      - .github/workflows/release-published.yml\n",
    "published validator path": "      - scripts/check-published-release.py\n",
    "published validator test path": "      - scripts/test-check-published-release.py\n",
    "published validator compilation": "            scripts/check-published-release.py \\\n",
    "published validator test execution": "          python3 scripts/test-check-published-release.py\n",
}
for description, marker in required_contract_once.items():
    count = contract_text.count(marker)
    expected = 2 if description in {
        "published workflow path",
        "published validator path",
        "published validator test path",
    } else 1
    if count != expected:
        raise SystemExit(
            f"{CONTRACT_WORKFLOW}: {description} marker occurred {count} times, expected {expected}"
        )
if "develop/0.11.0" in contract_text:
    raise SystemExit("release contracts must not depend on the retired 0.11 development branch")

print("Tagged, canonical-tag, and published-release contracts are complete.")
