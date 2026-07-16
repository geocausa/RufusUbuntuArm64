# Linux persistence planning foundation

Version 0.9 development includes a **read-only planner** for a deliberately narrow set of live Linux media. It does not create a persistence partition, edit boot configuration, format a target, or write to a USB drive. Its purpose is to make eligibility and geometry rules independently testable before those rules are admitted to the privileged writer.

## Initial compatibility scope

### Ubuntu casper

The planner accepts Ubuntu 20.04 or newer media only when all of the following are found:

- a regular kernel and initrd beneath `casper/`;
- a bounded, recognized GRUB, Syslinux, or systemd-boot configuration containing `boot=casper` on a kernel-argument line;
- `.disk/info` naming a supported Ubuntu release.

The planned contract is:

- kernel parameter: `persistent`;
- filesystem: ext4;
- filesystem label: `casper-rw`.

Ubuntu's current `casper(7)` manual documents the `persistent` parameter and `casper-rw` label. The official Rufus 4.15 implementation also formats its Ubuntu-like persistence partition as `casper-rw`.

### Debian live-boot

The planner accepts media with a regular kernel and initrd beneath `live/` and a recognized boot configuration containing `boot=live` on a kernel-argument line.

The planned contract is:

- kernel parameter: `persistence`;
- filesystem: ext4;
- filesystem label: `persistence`;
- root `persistence.conf`: `/ union`.

The Debian Live Manual requires the `persistence` boot parameter, the `persistence` volume label, and a root `persistence.conf`; `/ union` requests full overlay persistence.

## Read-only CLI

Mount the ISO read-only, or extract it into a local directory, then provide the intended target capacity:

```bash
rufusarm64-cli persistence plan \
  --image ubuntu.iso \
  --media-root /mnt/ubuntu-iso \
  --target-size 64G \
  --size 16G \
  --json
```

`--size 0` uses all aligned space remaining after the image and required partition-table metadata. Sizes use binary K/M/G/T units and must resolve to a whole MiB for a requested persistence partition.

The planner currently accepts only a plain raw-bootable ISOHybrid image. Compressed and virtual-disk inputs are rejected because the plan must describe the exact bytes that would be written.

## Partition-table checks

For MBR images the planner:

- verifies the MBR signature and every occupied primary entry;
- rejects invalid boot flags, zero, overflowing or overlapping extents, inconsistent GPT markers, and a full four-entry table;
- selects the first unused primary entry;
- places persistence after the complete image at a 1 MiB boundary;
- rejects a proposed partition that cannot be represented by the MBR 32-bit LBA fields.

For GPT images the planner additionally:

- validates primary and backup GPT header CRCs;
- validates and compares the primary and backup entry tables;
- checks disk GUID, table geometry, usable ranges, entry CRCs, unique partition GUIDs, and non-overlapping extents;
- requires a free GPT entry;
- reserves space to relocate the backup entry table and header to the end of the eventual target.

The minimum planned persistence partition is 1 GiB. The target and image sizes must be 512-byte aligned.

## Trust and safety boundary

This command is unprivileged and read-only. `--target-size` is a planning input, not a device identity or authorization. A future writer must independently reopen the exact source, inspect the actual target size and partition table, bind both identities, repeat every geometry and compatibility check, use no-symlink traversal for boot-file edits, and complete all source preparation before erasing anything.

A successful plan therefore means only **eligible for a future implementation**, not that persistence creation is currently available or that the media has passed physical boot testing.

## Deliberate exclusions

The initial planner refuses:

- Ubuntu releases older than 20.04 and Ubuntu-derived media without an explicit supported Ubuntu release marker;
- ambiguous media containing both casper and Debian live-boot layouts;
- unsupported boot configuration locations or generated/variable command lines it cannot classify safely;
- encrypted persistence, custom Debian persistence mounts, multiple stores, persistence files, and persistence-path variants;
- media whose MBR/GPT data are incomplete, inconsistent, overlapping, full, or not located where an append-only plan can preserve them.

References:

- Ubuntu `casper(7)`: <https://manpages.ubuntu.com/manpages/noble/man7/casper.7.html>
- Debian Live Manual, persistence: <https://live-team.pages.debian.net/live-manual/html/live-manual/customizing-run-time-behaviours.en.html#581>
- Rufus 4.15 persistence formatting: <https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/src/format.c>
