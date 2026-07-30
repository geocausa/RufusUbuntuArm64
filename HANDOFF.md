# RufusArm64 development handoff

Updated: 2026-07-30 07:22 Europe/London

This file is the durable restart point for ChatGPT/Connector2 development on
`geocausa/RufusUbuntuArm64`. Read it before changing files or running a
physical USB operation.

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

Begin the next distinct compatibility family with official openSUSE
Tumbleweed AArch64 DVD media.

Planned sequence:

1. Resolve a version-pinned official openSUSE AArch64 ISO, checksum and signing
   material. Avoid committing a rolling `Current` URL as qualified evidence.
2. Verify the signed checksum before admitting the artifact.
3. Run the read-only helper and headless Linux compatibility analyser.
4. Determine whether the image is ISO Image capable, DD-only, both, or safely
   refused.
5. Add generic handling only where the official artifact proves it necessary;
   avoid distribution-name special cases when a media-layout rule suffices.
6. Add exact filename, size, SHA-256, inspection and expected decision to the
   corpus.
7. Run focused tests, Go 1.22 compatibility, pinned Go 1.26.5 audit, full
   native ARM64 package/reproducibility tests and loop-device qualification.
8. Use `/dev/sda` for physical write/readback only after exact source and target
   identity checks and all pre-erasure validation pass.
9. Push a major green tranche and open a PR.

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

Current known target:

- Whole device: `/dev/sda`
- Model: `KINGSTON SNS4151S316G`
- Capacity: approximately 14.9 GiB
- Connection: SATA SSD in a USB enclosure
- Stable identity used by Rufus safety checks:
  `03cda7c90ec3517d84d817a9e761c369e5c53acf88bef4bd3873d43f0208b0de`
- Last completed media: Fedora Everything 44 aarch64
- Current filesystem/label: FAT32, `FEDORA44`

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
