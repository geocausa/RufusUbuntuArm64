# RufusArm64 development handoff

Updated: 2026-07-30 12:14 Europe/London

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

Continue the next distinct compatibility family with official openSUSE
Tumbleweed AArch64 DVD media.

Current progress:

- The pending corpus entry is pinned to
  `openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso`; do not return
  it to the rolling `Current` alias.
- The official detached checksum signature was accepted with `gpgv` using the
  openSUSE Project Signing Key fingerprint
  `AD48 5664 E901 B867 051A B15F 35A2 F86E 29B7 00A4`.
- The signed expected SHA-256 is
  `be9ff4dae638029557f5cb9d8e1c55fcc50f9c8ad1253c3d2e401fffcc41f547`;
  the mirror-reported size is `4099753984` bytes.
- Evidence files are under
  `/home/geoca/Downloads/opensuse-tumbleweed-aarch64-20260714/`. The resumable
  partial is named with the non-admissible `.iso.download` suffix and was
  `154697728` bytes at this checkpoint.
- A bounded sparse range probe showed an MBR/ISO9660 hybrid with a BIOS El
  Torito entry and provisionally classified it as `dd-only`. This is not corpus
  qualification: the complete artifact still requires full-byte SHA-256
  verification and exact helper/analyser execution.
- The installed `0.15.0~rc2` helper is stale for Fedora optical classification.
  Use the branch-built helper at
  `/home/geoca/Documents/RufusUbuntuArm64-corpus/dist/local-corpus-tools/rufusarm64-helper`
  or rebuild it from the active branch.
- Pending entries may now carry signed size/SHA-256 bindings. The corpus runner
  rejects a mismatched size before hashing or helper inspection, preventing an
  interrupted download with the final filename from producing a plausible
  compatibility decision.
- Checkpoint validation passed with Go 1.26.5: all Go packages, all 227 GUI
  tests, `staticcheck`, `actionlint`, `govulncheck` with no vulnerabilities,
  and the existing corpus baseline (`8` checked, `6` pending/missing).

Remaining sequence:

1. Resume the `.iso.download` transfer and verify the complete artifact against
   the signed SHA-256 before renaming it to the exact corpus filename.
2. Run the read-only helper and headless Linux compatibility analyser.
3. Determine whether the complete image is ISO Image capable, DD-only, both,
   or safely refused; do not promote the sparse-probe result by assumption.
4. Add generic handling only where the official artifact proves it necessary;
   avoid distribution-name special cases when a media-layout rule suffices.
5. Commit the exact inspection and expected decision, then run Go 1.22
   compatibility, pinned Go 1.26.5 audit, full native ARM64 package and
   reproducibility tests, and loop-device qualification.
6. Use a freshly enumerated and identity-bound sacrificial target for physical
   write/readback only after all pre-erasure validation passes.
7. Push a major green qualification tranche and open a PR.

Existing pending corpus families after Fedora:

- Linux Mint
- Bazzite
- Nobara
- openSUSE
- Nutanix
- umbrelOS

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

Current safety block observed on 2026-07-30:

- `/dev/sda` is now a different mounted 29.7 GiB `Generic STORAGE DEVICE`
  with a FAT volume labelled `UBUNTUX1E`.
- It does not match the qualified Kingston model, capacity or stable identity.
- Physical writes are disabled until a sacrificial target is deliberately
  selected, unmounted, enumerated and identity-bound again.

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
