# RufusArm64 development handoff

Updated: 2026-07-30 16:02 Europe/London

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
4. reassess deferred long-tail items—including Windows To Go and formats whose
   Linux implementation is currently incomplete—after the stable media paths
   and release pipeline are physically qualified.

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
- Active branch: `parity/opensuse-iso-corpus`
- Branch base: `742a542106daea0c5a9e2a308012b3d301b8bb51`
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

To resume the exact openSUSE artifact transfer without changing corpus claims:

```bash
rsync --partial --append-verify --human-readable --info=progress2 \
  rsync://ftp.icm.edu.pl/pub/Linux/opensuse/ports/aarch64/tumbleweed/iso/openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso \
  /home/geoca/Downloads/opensuse-tumbleweed-aarch64-20260714/openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso.download
printf '%s  %s\n' \
  be9ff4dae638029557f5cb9d8e1c55fcc50f9c8ad1253c3d2e401fffcc41f547 \
  /home/geoca/Downloads/opensuse-tumbleweed-aarch64-20260714/openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso.download | sha256sum -c -
mv -- \
  /home/geoca/Downloads/opensuse-tumbleweed-aarch64-20260714/openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso.download \
  /home/geoca/Downloads/opensuse-tumbleweed-aarch64-20260714/openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso
```

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

PR #421 merged as `89686ef31ff8750f6079296f080c50b38786f56e`. The
active branch is `release/verified-update-download`, based on merged `main`.
Continue the signed-release completion path without introducing automatic
installation or CI-held private keys.

Implemented in this tranche:

- `DownloadReleasePackage` adapts the exact authenticated ARM64 package record
  to the existing reviewed acquisition downloader rather than creating another
  network or filesystem writer.
- A private immutable trust snapshot is created only after threshold signature
  verification. Exported inspection fields may be changed by an embedding
  caller without changing the trusted version, package URL, size, SHA-256,
  metadata digest or signing-key evidence used by update decisions/downloads.
- `rufusarm64-cli update download` requires the full sequential root chain,
  signed release envelope, current version and rollback floor. It refuses a
  same-version or older release before any network request.
- The command supports exact destination selection, safe replacement, resumable
  transfer, JSON progress or final JSON, and reports release/metadata evidence.
  It never requests privilege or invokes a package manager.
- The reused downloader enforces signed redirect hosts, HTTPS/TLS policy, exact
  response and range semantics, available-space preflight, cancellation,
  bounded owner-owned partial files, exact size/SHA-256, synchronization,
  atomic no-replace publication and verified reuse.
- Focused tests pass for authenticated download/readback/reuse, unauthenticated
  object refusal, same-version refusal, exact CLI binding and post-verification
  mutation resistance.
- Final local validation passed: complete Go 1.22.12 suite in an isolated
  mount namespace; Go 1.26.5 race/vet, staticcheck, actionlint and govulncheck
  with no vulnerabilities; all Go and GUI tests; native ARM64 package checks;
  exact bounded ISO corpus; and byte-for-byte reproducible Debian packaging.
  The temporary pinned UEFI prerequisite was restored from a previously green
  package only after exact checksum verification and removed before commit.

Remaining sequence:

1. Finish documentation and run Go 1.22, race/vet/static/vulnerability, GUI,
   package, reproducibility and exact workflow-contract validation.
2. Commit, push and open a dedicated verified-download PR; accept only exact-head
   green CI before merge.
3. Design owner-only persistent release metadata rollback state and authenticated
   network refresh. Do not rely indefinitely on caller-supplied rollback floors.
4. Define and perform the production offline root/release key ceremony, then
   commit only public roots and threshold-signed envelopes.
5. Make release publication refuse any staged artifact graph that differs from
   the committed signed envelope.
6. Keep package installation, privilege, package-manager behavior and rollback
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

At PR #419 head `ea07169915ec67bbc3b4ce5c3fcace2d2e04b1f9`:

- all GitHub checks passed;
- Go 1.22 compatibility passed;
- Go 1.26.5 staticcheck/actionlint/govulncheck passed with no vulnerabilities;
- all 226 Python GUI tests passed;
- native ARM64 Go/package suite passed;
- reproducible Debian package was confirmed;
- strict corpus passed for Ubuntu, Debian, Fedora and five deterministic
  fixtures;
- physical Ubuntu MBR/NTFS, Debian GPT/FAT32 and Fedora optical-only MBR/FAT32
  write/readback passed on `/dev/sda`.

## New-chat instruction

A concise restart request is:

> Connect to Connector2, open `/home/geoca/Documents/RufusUbuntuArm64-corpus`,
> read `HANDOFF.md`, verify Git and USB state, and resume the
> `parity/opensuse-iso-corpus` tranche from the documented next objective.

Do not redo PR #418 or #419, and do not begin by recloning unless the existing
worktrees are genuinely missing or corrupt.
