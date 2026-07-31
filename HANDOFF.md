# RufusArm64 development handoff

Updated: 2026-07-30 21:08 Europe/London

This file is the durable restart point for ChatGPT/Connector2 development on
`geocausa/RufusUbuntuArm64`. Read it before changing files or running a
physical USB operation.

## Project purpose and operating mandate

Build `RufusUbuntuArm64` into a native Linux/ARM64 USB-media tool with practical
functional parity with upstream Windows Rufus. Port or independently implement
features wherever Linux provides a safe, auditable equivalent. When a Windows-
only provider, firmware dependency, licensing boundary, architecture limitation,
or unavailable Linux primitive prevents faithful implementation, record the
limitation explicitly in the parity ledger, keep the user-facing claim bounded,
and continue to the next tractable feature rather than blocking the programme.

The implementation should prefer upstream-compatible behaviour and defaults,
but must not imitate unsafe assumptions merely for cosmetic parity. Destructive
operations remain identity-bound, source-authenticated, cancellation-aware and
revalidated immediately before erasure.

## Scope and evidence model

The programme includes the complete product surface, not only raw ISO copying:

- Windows and Linux installation-media creation;
- ISO Image and DD Image modes;
- partition scheme, target-system, filesystem, cluster and label behaviour;
- Windows setup customisation where it can be reproduced safely;
- persistence, FreeDOS, non-bootable formatting, imaging, backup and supported
  container formats;
- Secure Boot, UEFI, bootloader and runtime-integrity validation;
- bad-block/capacity qualification and guarded physical-device workflows;
- official-image acquisition, checksums, packaging, updates, localisation and
  release integrity;
- representative compatibility evidence for materially distinct media layouts.

Do not attempt to test every distribution name or every point release. Qualify
every materially distinct boot-media construction family, add popular official
artifacts as immutable evidence, and treat unknown layouts conservatively.
Evidence levels must remain separate:

1. read-only parser/analyser evidence;
2. loop-device write and reopen evidence;
3. physical USB write/readback evidence;
4. actual firmware boot, Secure Boot and installer-completion evidence.

Never claim a higher level from a lower-level test.

## Direction and roadmap

The current strategic sequence is:

1. complete the Linux ISO compatibility corpus across distinct media families;
2. close release/product-completion gaps such as signed artifacts, verified
   updates, the production official-image catalogue, localisation and portable
   distribution;
3. continue high-value upstream Rufus parity tranches;
4. physically qualify the experimental Windows To Go ARM64 path and continue
   only those long-tail formats that have a trustworthy Linux-native implementation.

Development policy: implement a coherent major tranche, test it locally on the
native ARM64 host, use loop devices and the sacrificial USB where the evidence
benefit is meaningful, commit reviewable changes, push them, and require green
CI before merge. Keep unsupported or unproven behaviour visibly marked instead
of silently approximating it.

## Resume pointer

- Repository: `https://github.com/geocausa/RufusUbuntuArm64`
- Connected-machine user: `geoca`
- Primary workspace: `/home/geoca/Documents/RufusUbuntuArm64`
- Active feature worktree: `/home/geoca/Documents/RufusUbuntuArm64-corpus`
- Active branch: `release/signed-publication-enforcement`
- Branch base: `32487b04867f6111f5c15d92bf07b21935376c1e`
- Remote: `origin`

After Connector2 access is restored, start with:

```bash
cd /home/geoca/Documents/RufusUbuntuArm64-corpus
git fetch origin
git status --short --branch
git log -5 --oneline --decorate
cat HANDOFF.md
lsblk -o NAME,PATH,TYPE,SIZE,MODEL,TRAN,FSTYPE,LABEL,SERIAL,MOUNTPOINTS
```

The openSUSE corpus transfer and qualification are complete. Do not resume the retired transfer command or alter corpus evidence unless a new dedicated tranche requires it.

The active branch should be checked out. Do not reset or delete local files
until `git status` has been inspected.

## Completed parity tranches

- PR #418, filesystem-specific Unicode labels, merged as
  `f6366cc1f7bfdd06a084e787b2ea7adc20e54851`.
- PR #419, Linux ISO compatibility corpus and optical-only ISO support, merged
  as `742a542106daea0c5a9e2a308012b3d301b8bb51`.
- PR #419 qualified official Ubuntu 26.04 ARM64, Debian 13.6 ARM64 and Fedora
  Everything 44 aarch64 media plus deterministic boundary fixtures.
- Fedora exposed and fixed a real bug where every optical-only ISO was treated
  as Windows media. Windows mode now requires bounded Windows installation
  evidence; optical-only Linux UEFI media can use ISO Image mode without DD.

Relevant project trackers:

- GitHub issue #412: Rufus 4.15 parity audit/remediation tracker.
- `docs/linux-iso-corpus.md`
- `docs/linux-iso-corpus.json`
- `docs/upstream-rufus-parity.json`

## Current objective

PR #424 merged as `32487b04867f6111f5c15d92bf07b21935376c1e`. The
active branch is `release/signed-publication-enforcement`, based on merged
`main`. This tranche closes the software-side release-publication gap without
placing private release keys in CI.

Implemented in this tranche:

- `rufus-channel-admin verify release-assets` verifies an exact staged or
  downloaded asset directory against threshold-authenticated release metadata,
  including tag, commit, sorted inventory, sizes and SHA-256 values.
- Asset verification is directory-descriptor rooted and refuses symlinks, hard
  links, non-regular or empty files, owner mismatch, group/world-writable paths,
  file or directory replacement, permission/timestamp mutation, inventory
  drift, and content substitution while hashing.
- `scripts/verify-release-publication.sh` checks the packaged channel and
  bootstrap root against the signed publication, verifies the root/release
  chain, deterministically rebuilds the metadata directory, compares every
  public byte, and optionally verifies the complete release asset graph.
- The canonical-tag workflow defers `v<version>` until the separately reviewed
  `release-metadata-v<version>` tag exists, verifies that signed metadata against
  the final `main` commit, then creates the immutable canonical tag and
  dispatches the audited release workflow.
- The release workflow verifies freshly reproduced assets before upload. The
  read-only published-release workflow binds the release tag to its exact commit,
  downloads the public assets, runs the existing GitHub release contract, and
  verifies the threshold-signed graph again.
- Workflow-integrity contracts, operator documentation, signed-update
  documentation, roadmap, changelog and parity ledger are synchronized.

Validation completed for this tree on 2026-07-30:

- Go 1.22.12 complete compatibility suite in a root-owned private mount
  namespace that hides the installed Rufus package;
- Go 1.26.5 complete race suite, three shuffled repetitions, vet and coverage;
- focused release-asset and administrator tests under Go 1.22.12 and Go 1.26.5;
- all 227 GUI Python tests and release/publication Python contract tests;
- gofmt, `git diff --check`, JSON validation, Bash syntax, shellcheck and
  actionlint;
- staticcheck and govulncheck (`No vulnerabilities found`);
- native ARM64 package validation and byte-for-byte reproducible Debian package.

The package-private `uefi-md5sum` prerequisite was supplied only through a
verified temporary directory copied from the installed green package. Its exact
40960-byte size and pinned SHA-256 were checked, both sidecars passed, the
installed package was hidden from tests, and the temporary directory was
removed automatically.

Remaining sequence:

1. Keep the completed local tranche unpushed until the user has reviewed the
   validation results, commit summary and proposed remote action.
2. After explicit approval, push the branch, open a dedicated PR and require
   exact-head green CI before merge.
3. Perform the production offline-key ceremony separately, then publish only
   reviewed public roots, the enabled pinned channel and threshold-signed
   metadata. No private key enters source, CI, packages or artifacts.
4. Keep package installation, privilege, package-manager behavior and rollback
   as a separate high-risk tranche.

The sacrificial USB still contains the verified openSUSE Tumbleweed AArch64
image. Do not overwrite it without explicit authorization and fresh identity
re-enumeration.

## Machine/toolchain state

- Machine architecture: native `aarch64`.
- Minimum Go toolchain: Go 1.22.12.
- Patched development/audit toolchain: Go 1.26.5.
- The system default `go` may still report Go 1.26.0. For audit and final
  validation, explicitly use `GOTOOLCHAIN=go1.26.5`.
- Pinned audit tools are installed in `/home/geoca/.local/bin`:
  - `staticcheck v0.7.0`
  - `govulncheck v1.6.0`
  - `actionlint v1.7.12`
- Local package/loop/QEMU/filesystem/EDK2 dependencies are installed.
- The host has an installed RufusArm64 package. Some clean tests must isolate
  `/usr/lib/rufusarm64/wimlib-imagex` with a private mount namespace so the
  installed binary cannot mask packaging omissions.
- Use an effective `umask 0022` for the complete Go suite because secure-path
  tests intentionally reject group/world-writable temporary roots.

## Physical USB state and safety

Previously qualified sacrificial target:

- Whole device at the time: `/dev/sda`
- Model: `KINGSTON SNS4151S316G`
- Capacity: approximately 14.9 GiB
- Connection: SATA SSD in a USB enclosure
- Stable identity used by Rufus safety checks:
  `03cda7c90ec3517d84d817a9e761c369e5c53acf88bef4bd3873d43f0208b0de`
- Last completed media: Fedora Everything 44 aarch64
- Last known filesystem/label: FAT32, `FEDORA44`

Current user-authorized sacrificial target, observed on 2026-07-30:

- Whole device: `/dev/sda`
- Model/vendor: `Generic STORAGE DEVICE`
- Capacity: `31914983424` bytes (approximately 29.7 GiB)
- Connection: removable USB 2.0 microSD card reader
- Current filesystem/label: mounted FAT volume `UBUNTUX1E`
- Stable identity from the branch-built helper:
  `84d18636c43baa4b9c72e73a8f53f7f3be7d13789f0b8d11ec0dd5189146b5be`
- The user explicitly designated this attached device as sacrificial. An
  identity-bound destructive dry run passed against the qualified Ubuntu 26.04
  ARM64 source without writing data.
- Physical writing is permitted only after the intended source passes its exact
  signed size/SHA-256 binding, the mounted child is unmounted, the device is
  enumerated again, and the identity above still matches exactly.

The internal system disk is not `/dev/sda`. Nevertheless, never assume target
identity from the pathname alone. Before every destructive operation:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,MODEL,TRAN,FSTYPE,LABEL,SERIAL,MOUNTPOINTS
```

Then refresh the Rufus device identity and require an exact match. Physical
writes must continue using the package helper's identity, cancellation and
pre-erasure validation contracts. Do not bypass them merely because the USB is
sacrificial.

Archived local physical evidence is under:

`/home/geoca/Documents/RufusUbuntuArm64/dist/audit-logs/`

Notable Fedora record:

`/home/geoca/Documents/RufusUbuntuArm64/dist/audit-logs/local-corpus/physical-fedora-mbr-fat32.jsonl`

## Last fully green validation

For the `release/signed-publication-enforcement` tree validated on 2026-07-30:

- the complete isolated Go 1.22.12 and Go 1.26.5 matrices passed;
- staticcheck, actionlint and govulncheck passed with no vulnerabilities;
- all 227 Python GUI tests and all release/publication contract tests passed;
- shell, formatting, JSON and workflow-integrity validation passed;
- native ARM64 package checks passed;
- byte-for-byte reproducible Debian packaging was confirmed;
- no physical USB operation was performed.

## New-chat instruction

A concise restart request is:

> Connect to Connector2, open `/home/geoca/Documents/RufusUbuntuArm64-corpus`,
> read `HANDOFF.md`, inspect Git status and the complete diff, and resume the
> `release/signed-publication-enforcement` tranche from the documented remaining
> sequence. Do not push before showing the user the validation and proposed
> remote action.

Do not redo merged release-refresh work, and do not begin by recloning unless
the existing worktrees are genuinely missing or corrupt.
