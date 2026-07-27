# Pinned FreeDOS 1.4 payload provenance

This directory records the corresponding source and package metadata for the
minimal FreeDOS payload reviewed for RufusArm64. The payload is not yet exposed
by a command, Polkit action, Debian runtime path, or GTK control.

## Reviewed origin

The source distribution is the official `FD14-FullUSB.zip` release with
SHA-256:

`cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff`

Inside `FD14FULL.img`, the first active FAT32 partition starts at logical sector
63. The reviewed files come from:

- `PACKAGES/BASE/FREECOM.ZIP` → `BIN/COMMAND.COM`;
- `PACKAGES/BASE/KERNEL.ZIP` → `BIN/KERNL386.SYS`;
- the matching `SOURCE/.../SOURCES.ZIP`, LSM metadata, and GPLv2 text in those
  same official packages.

Rufus 4.15 changes only byte offset `0x0d` of `KERNL386.SYS` from `0x00` to
`0x01`, enabling `FORCELBA`, and publishes the result as `KERNEL.SYS`. The
resulting `KERNEL.SYS` and `COMMAND.COM` bytes match the Git objects pinned in
Rufus commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`.

## Offline verification

Repository validation requires no network access:

```sh
python3 scripts/extract-freedos-payload.py --check
```

To reproduce the files from a locally supplied official archive, install
`mtools` and run:

```sh
python3 scripts/extract-freedos-payload.py \
  --archive /path/to/FD14-FullUSB.zip --write --check
```

The extractor verifies the outer archive, MBR and partition offset, nested
package archives, exact package members, payload sizes and SHA-256 values, Git
blob identities, source archives, licence members, and the one-byte kernel
patch. It does not download content, execute DOS code, or access a device.

## Update rule

A future FreeDOS update must be a new reviewed tranche. It must pin a new
official distribution hash, regenerate `PAYLOADS.json`, retain the corresponding
source archives and licence material, compare payloads with the chosen Rufus
reference, rerun ordinary-file tamper tests, and pass the complete repository
CI matrix before merge.
