# El Torito UEFI boot-image extraction core

Status: **read-only planning and caller-supplied extraction only**. This tranche does not select a write mode, open a path, mount an image, access a target, or claim that firmware will boot the extracted bytes.

Upstream behavioral reference: `pbatard/rufus` 4.15 build 2396, commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`, especially `src/iso.c` and the pinned libcdio El Torito parser in `src/libcdio/iso9660/iso9660_fs.c`.

## Purpose

Some firmware-update, recovery, and nonstandard optical images carry their usable UEFI filesystem only as an El Torito boot image rather than as ordinary files in the ISO tree. Rufus exposes these images through its optical parser and uses them for limited compatibility recovery.

`internal/imaging.PlanElToritoUEFIImage` provides a Linux-native, bounded parser for one unambiguous EFI no-emulation boot image. `ExtractElToritoUEFIImage` streams exactly that planned extent to a caller-supplied writer and rehashes the source while doing so.

## Descriptor and catalog validation

The planner:

- scans ISO 9660 volume descriptors only at 2,048-byte boundaries from sector 16 through the existing bounded descriptor limit;
- requires a consistent primary-volume space size in both little- and big-endian ISO fields;
- requires exactly one effective El Torito boot-record catalog location;
- requires the exact El Torito boot-system identifier and a non-zero catalog LBA inside the declared volume;
- reads exactly one 2,048-byte catalog sector;
- validates header id `0x01`, a standard platform id, the `0x55AA` key bytes, and the 16-bit validation-entry checksum;
- parses the initial/default entry and bounded section headers `0x90` / `0x91`;
- rejects unsupported section-entry extensions, invalid boot indicators, reserved media bits, invalid section counts, and non-zero data after a final section.

## EFI selection policy

The initial implementation accepts only:

- platform id `0xEF` (EFI);
- boot indicator `0x88`;
- media type `0` (no emulation);
- a non-zero image LBA;
- exactly one matching entry.

Zero candidates are refused. Multiple EFI no-emulation candidates are refused as ambiguous rather than selecting one silently. Floppy and hard-disk emulation entries remain a later, separately reviewed compatibility tranche.

## Rufus/libcdio small-count compatibility

El Torito records declare image size in 512-byte virtual sectors. Some UEFI images incorrectly declare a count of zero or one even though the image is much larger.

The pinned Rufus/libcdio implementation treats such an entry as extending to the closest later boot-image LBA, or to the end of the declared ISO volume, only when the gap is at least `0x1000` ISO sectors (8 MiB). The Linux-native planner preserves that exact compatibility threshold.

If the gap is smaller, the declared count is used. A zero-length image that does not meet the expansion rule is refused.

## Bounds and source integrity

Every catalog and image extent must fit both the declared ISO volume and the caller-supplied source size. Offset addition, sector conversion, and range end are checked before reads.

Planning hashes:

- the complete catalog sector with SHA-256;
- the exact selected image extent with SHA-256;
- all structural and extent fields into a deterministic plan SHA-256.

Extraction plans first, then streams the same range with 64 KiB bounded reads while checking cancellation. It compares the extracted image digest with the planning digest in constant time, then rereads and rehashes the boot catalog so a catalog change cannot invalidate the selected extent silently. A changed source is reported even though a caller-supplied writer may already have received bytes; atomic publication remains the caller's responsibility.

## Explicit non-goals

This tranche performs no:

- ISO path opening or source-identity lease;
- automatic firmware-update or write-mode selection;
- filesystem probing inside the extracted image;
- mount, loop-device, USB-device, or privileged operation;
- destination publication or overwrite;
- UEFI execution, Secure Boot policy evaluation, or hardware compatibility claim.

A later integration tranche may combine this plan with the repository's existing source identity, FAT/UEFI inspection, runtime-integrity, and guarded publication primitives.

## Acceptance coverage

Synthetic fixtures cover:

- validation-platform and EFI section entries;
- exact extraction and deterministic plan hashes;
- Rufus-compatible 8 MiB small-count expansion;
- bad validation checksums and key bytes;
- unsupported emulation media;
- ambiguous EFI entries;
- catalog and image extents outside the declared volume;
- zero-length refusal;
- nil and cancelled contexts;
- writer failure;
- image and catalog mutation between planning and extraction;
- fuzz no-panic parsing.

Complete exact-head Go 1.22 CI, native ARM64 execution, static/vulnerability audit, reproducible packaging, and both loop qualification suites remain mandatory before merge.
