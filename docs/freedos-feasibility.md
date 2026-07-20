# FreeDOS media feasibility on Ubuntu ARM64

Status: **feasible in principle; the ordinary-file media contract is verified, but device implementation and GTK exposure are not yet approved**.

This record answers whether an Ubuntu ARM64 host can construct Rufus-style FreeDOS media without executing x86 software on the host or weakening the existing removable-drive safety boundary.

## Platform boundary

FreeDOS 1.4 requires an Intel-compatible processor and BIOS or UEFI Legacy/CSM firmware. Media produced by this work would target x86 PCs only. It would not boot an ARM64 computer and would not support UEFI-only PCs.

The application must state these limits before planning, authentication, or erasure. Software-only structural checks must not be described as proof that a particular physical PC will boot.

## Pinned upstream evidence

The feasibility checkpoints pin these references in `internal/freedos/manifest.go` and the corresponding vendor records:

- FreeDOS 1.4 official FullUSB archive SHA-256: `cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff`;
- FreeDOS 1.4 official LiteUSB archive SHA-256: `857dcd2ebf9d3d094320154db5fb5b830acba6fb98f981a95a0ca7ab3350338b`;
- Rufus reference commit: `6d8fbf98305ff37eb531c45cbd6ff44563c53917`;
- FreeDOS kernel source commit: `d6791add2043c9d7b584d840a8ffaf8829fd2bdc`;
- FreeCOM source commit: `04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`;
- Rufus FreeDOS `KERNEL.SYS` Git blob: `6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd`;
- Rufus FreeDOS `COMMAND.COM` Git blob: `255525acc562e0411e3e5f000bc1ba788733056d`;
- Rufus FAT32 formatter source Git blob: `fa75f16eecb194f0854eacd1ab4e76d0ae7aa602`.

The official FreeDOS download page identifies FullUSB and LiteUSB as the distributions intended for real hardware and publishes the archive hashes above. Rufus 4.15 documents that its embedded payload was extracted from FreeDOS 1.4 FullUSB.

## Why ARM64 host construction is possible

Rufus does not need to run FreeDOS on the Windows host. Its implementation formats the target, installs BIOS boot code, and copies embedded files. The root payload is `KERNEL.SYS` and `COMMAND.COM`; locale utilities are optional product-scope additions.

The same architecture can be implemented with native Go and standard Ubuntu ARM64 filesystem tools:

1. discover and identity-bind one removable whole disk;
2. build and display a deterministic MBR/FAT plan without privileges;
3. require exact destructive confirmation;
4. authenticate through a dedicated Polkit action;
5. retain the whole-disk descriptor lock and revalidate immediately before erasure;
6. create one active MBR partition and a FAT filesystem;
7. install pinned FreeDOS MBR and partition boot code without executing DOS utilities;
8. copy pinned payload bytes and verify them by size and SHA-256;
9. verify the partition table, FAT metadata, active flag, boot signatures, allocation chains, payload placement, and kernel configuration;
10. report that the result is BIOS/Legacy x86 media and is not validated on physical hardware.

## Initial implementation scope

The narrowest reviewed first version is:

- MBR only;
- one active primary partition;
- FAT32 only;
- 512-byte logical sectors only;
- `KERNEL.SYS` and `COMMAND.COM` in the filesystem root;
- English-only minimal shell media initially;
- no host execution, emulator, Wine, DOSBox, QEMU, or downloaded installer at runtime;
- no fixed-disk override in the graphical path;
- no UEFI boot claim;
- no reuse of the ordinary image writer unless a later design adopts a fully pinned deterministic disk-image publication path.

## Resolved boot-code provenance checkpoint

The default Rufus 4.15 FreeDOS path is pinned and reproducible from GPL `ms-sys` source at the reviewed Rufus commit:

- Rufus MBR bootstrap: 440 bytes from `mbr_rufus.h`, written without replacing the disk signature or partition table;
- MBR layout contract: the first partition is active and uses FAT32 LBA type `0x0c`;
- FAT32 prefix: 11 bytes from `br_fat32_0x0.h` at offset `0x00`;
- FreeDOS FAT32 loader: 918 bytes from `br_fat32fd_0x52.h` at offset `0x52`;
- FreeDOS continuation: 528 bytes from `br_fat32fd_0x3f0.h` at offset `0x3f0`;
- both the primary boot region and the backup beginning at logical sector 6 are patched and verified;
- the offline extractor, source hashes, Git blob IDs, binary hashes, BPB-preservation tests, MBR-metadata tests, and tamper tests are committed.

## Resolved kernel configuration checkpoint

The pinned FreeDOS kernel source establishes the `KERNEL.SYS` configuration layout without reverse engineering or executing the payload:

- `kernel/kernel.asm` identifies byte zero of `KERNEL.SYS`, emits a two-byte short jump, then writes the `CONFIG` signature, the configuration-size word, and the configuration fields;
- `hdr/kconfig.h` places `ForceLBA` after the three one-byte `DLASortByDriveNo`, `InitDiskShowDriveAssignment`, and `SkipConfigSeconds` fields;
- `sys/fdkrncfg.c` reads the configuration structure from file offset 2 and treats `FORCELBA` as present when the configuration area contains at least four fields;
- `docs/sys.txt` defines `FORCELBA=1` as using extended INT 13 LBA addressing whenever possible.

Those source-backed offsets place `ForceLBA` at file offset `0x0d`. `vendor/freedos-kernel/KERNEL-CONFIG.json` pins the exact source commit and Git blob IDs used for the conclusion. `internal/freedos/kernel.go` parses the header, rejects truncated or malformed configuration areas, requires a binary setting, requires the reviewed Rufus value `0x01`, and independently requires the exact pinned Rufus `KERNEL.SYS` Git blob identity.

## Resolved payload provenance checkpoint

The official checksum-pinned FullUSB archive is reproduced through its active FAT32 partition and nested BASE packages:

- `COMMAND.COM` is extracted from `FREECOM.ZIP` and matches the pinned Rufus Git object;
- `KERNL386.SYS` is extracted from `KERNEL.ZIP` with `FORCELBA` initially `0x00`;
- `KERNEL.SYS` changes only offset `0x0d` to `0x01` and then matches Rufus exactly;
- payload sizes, SHA-256 values, package hashes, Git blob IDs, source archives, LSM metadata, and GPLv2 texts are pinned;
- the committed extractor supports network-free repository checking and deterministic regeneration from a locally supplied official archive;
- Go validation rejects any altered payload byte, applies the source-backed kernel verifier, and returns only defensive copies.

Detailed records are in `docs/freedos-payload-provenance.md` and `vendor/freedos/PAYLOADS.json`.

## Resolved FAT32 geometry and structural-verification checkpoint

The first ordinary-file media contract is source-pinned in `vendor/rufus/FREEDOS-FAT32-GEOMETRY.json` and implemented in `internal/freedos/media.go`:

- one active FAT32-LBA MBR partition starts at sector 2048 and leaves a 2048-sector tail reservation;
- the initial contract supports 512-byte logical sectors, legacy CHS translation using 63 sectors per track and 255 heads, and the Rufus FAT32 cluster-size table;
- two FATs, root cluster 2, FSInfo sector 1, backup boot sector 6, and a reserved-plus-FAT system area rounded up so the data region begins on a 1 MiB boundary are required;
- the calculated geometry must contain at least 65,536 clusters, fit the 28-bit FAT32 cluster field, and remain below the 32-bit FAT32 and MBR LBA limits;
- the whole-image verifier checks the exact MBR/PBR code, LBA and CHS fields, hidden-sector and BPB geometry, primary and backup boot regions and FSInfo sectors, identical FAT copies, reserved entries, root records, hidden/system payload attributes, contiguous allocation chains, exact payload bytes, zero final-cluster slack, free-cluster accounting, and absence of orphan allocations;
- the deterministic ordinary-file fixture exercises the exact 65,536-cluster lower boundary and rejects MBR, BPB, FSInfo, FAT, directory, allocation, payload, and orphan-cluster tampering.

All completed checkpoints operate on ordinary bytes only. They do not authorize a device operation or establish that a physical PC will boot.

## Unresolved gates

Implementation remains blocked until all of these are resolved:

1. **Safety integration.** Build a dedicated identity-bound executor that retains root-disk refusal, descriptor locking, final pre-destructive revalidation, guarded cancellation, media-changed reporting, and complete final readback. Do not widen the ordinary image writer.
2. **Release maintenance.** Measure installed package impact, define the payload/source update procedure and cadence, and confirm the final Debian copyright and source-distribution contract before runtime installation.
3. **Product exposure.** Add terminal and GTK workflows only after the executor and real loop-device structural qualification pass. The graphical path must have no fixed-disk override and must disclose the x86 BIOS/Legacy-only boundary before authentication.
4. **Physical evidence.** Treat successful boot on representative x86 BIOS/Legacy hardware as a separate evidence claim, never as a consequence of software verification.

## Gate decision

The feasibility gate is **positive for deterministic ARM64-host construction and ordinary-file verification**. No x86 execution is required on the host, and the complete reviewed media structure can be expressed and rejected byte-for-byte in native Go.

It is **not device-implementation-green** until safety integration, real loop-device qualification, and release package planning are complete. Until then there must be no FreeDOS command, Polkit action, runtime payload installation, GTK option, release commitment, or physical-boot claim.

## Primary references

- FreeDOS 1.4 downloads and verification hashes: `https://www.freedos.org/download/` and `https://www.freedos.org/download/verify.txt`
- Rufus FreeDOS extraction implementation: `https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/src/dos.c`
- Rufus FAT32 formatter: `https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/src/format_fat32.c`
- Rufus FreeDOS payload provenance note: `https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/res/freedos/readme.txt`
- FreeDOS kernel and SYS documentation: `https://github.com/FDOS/kernel/tree/d6791add2043c9d7b584d840a8ffaf8829fd2bdc`
- FreeCOM source: `https://github.com/FDOS/freecom/tree/04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`
