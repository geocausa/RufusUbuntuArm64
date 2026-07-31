# El Torito UEFI boot-image extraction core

Status: **software implemented for the bounded Linux ISO Image mode profile**. Physical firmware boot and Secure Boot acceptance remain separate qualification evidence.

Upstream behavioral reference: `pbatard/rufus` 4.15 build 2396, commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`, especially `src/iso.c` and the pinned libcdio El Torito parser in `src/libcdio/iso9660/iso9660_fs.c`.

## Purpose

Some firmware-update, recovery, and nonstandard optical images carry their usable UEFI filesystem only as an El Torito boot image rather than as ordinary files in the ISO tree. Rufus exposes these images through its optical parser and uses them for limited compatibility recovery.

`internal/imaging.PlanElToritoUEFIImage` provides a Linux-native, bounded parser for one unambiguous EFI no-emulation boot image. `ExtractElToritoUEFIImage` streams exactly that planned extent and rehashes the source. Linux ISO Image mode now consumes this evidence end to end: ordinary inspection publishes the exact plan or refusal before authentication, and the privileged writer extracts, syncs, read-only mounts, verifies, inventories, merges, copies, and reads back the overlay under the existing source and target identity boundaries.

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

## Integrated write-path contract

When the mounted ISO tree already contains the architecture fallback path, no overlay is created. Otherwise the writer:

- requires the held, identity-bound ISO descriptor and the same complete source SHA-256 used by the surrounding operation;
- extracts the exact planned image to an owner-only, no-follow file inside the private workspace;
- syncs and verifies its exact planned size;
- mounts it through a loop device with `ro,nosuid,nodev,noexec` and verifies target, loop source, FAT filesystem type, and mount options with `findmnt`;
- inventories and hashes the mounted FAT tree using the same architecture and path policy as the ISO tree;
- accepts byte-identical duplicates only, and rejects every exact-content conflict or case-folded path collision across the two roots;
- retains both approved source roots through transactional copy and destination readback; and
- unmounts and removes the extracted image before the surrounding workspace is removed.

The path is available to Automatic, FAT32, and NTFS Linux ISO Image modes. A strict parser refusal disables the graphical ISO Image choice before authentication. Hybrid media can still retain explicit DD mode; optical-only media with no admitted UEFI path are refused rather than raw-written accidentally.

## Remaining non-goals

The bounded implementation still does not support floppy- or hard-disk-emulation El Torito entries, multiple candidate EFI images, BIOS/CSM extraction, arbitrary firmware-update payload semantics, UEFI execution, Secure Boot policy acceptance, or universal physical compatibility. These are not inferred from successful software extraction.

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
- fuzz no-panic parsing;
- strict plan/refusal JSON publication through ordinary image inspection;
- ISO-tree plus FAT-overlay multi-root merge, identical-duplicate admission, collision refusal, and approved-root copy validation;
- an actual generated fallback-only El Torito ISO mounted and copied through the production path; and
- a complete privileged loop transaction with partitioning, FAT32 formatting, overlay copy, SHA-256 readback, detach/reopen, filesystem probing, and final read-only file verification.

Exact-head Go 1.22 CI, native ARM64 execution, static/vulnerability audit, reproducible packaging, and the permanent ISO Image loop workflow remain mandatory for each merge. None of those software gates is recorded as firmware boot evidence.
