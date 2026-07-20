# FreeDOS media feasibility on Ubuntu ARM64

Status: **feasible in principle, not yet approved for implementation or GTK exposure**.

This record answers whether an Ubuntu ARM64 host can construct Rufus-style FreeDOS media without executing x86 software on the host or weakening the existing removable-drive safety boundary.

## Platform boundary

FreeDOS 1.4 requires an Intel-compatible processor and BIOS or UEFI Legacy/CSM firmware. Media produced by this work would target x86 PCs only. It would not boot an ARM64 computer and would not support UEFI-only PCs.

The application must state these limits before planning, authentication, or erasure. Software-only structural checks must not be described as proof that a particular physical PC will boot.

## Pinned upstream evidence

The first checkpoint pins these references in `internal/freedos/manifest.go`:

- FreeDOS 1.4 official FullUSB archive SHA-256: `cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff`;
- FreeDOS 1.4 official LiteUSB archive SHA-256: `857dcd2ebf9d3d094320154db5fb5b830acba6fb98f981a95a0ca7ab3350338b`;
- Rufus reference commit: `6d8fbf98305ff37eb531c45cbd6ff44563c53917`;
- FreeDOS kernel source commit: `d6791add2043c9d7b584d840a8ffaf8829fd2bdc`;
- FreeCOM source commit: `04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`;
- Rufus FreeDOS `KERNEL.SYS` Git blob: `6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd`;
- Rufus FreeDOS `COMMAND.COM` Git blob: `255525acc562e0411e3e5f000bc1ba788733056d`.

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
9. verify the partition table, FAT metadata, active flag, boot signatures, payload placement, and kernel configuration;
10. report that the result is BIOS/Legacy x86 media and is not validated on physical hardware.

## Initial implementation scope under consideration

The narrowest supportable first version is:

- MBR only;
- one active primary partition;
- FAT32 only, unless source-backed testing demonstrates a necessary FAT16 boundary;
- `KERNEL.SYS` and `COMMAND.COM` in the filesystem root;
- English-only minimal shell media initially;
- no host execution, emulator, Wine, DOSBox, QEMU, or downloaded installer at runtime;
- no fixed-disk override in the graphical path;
- no UEFI boot claim;
- no reuse of the ordinary image writer unless the final design becomes a fully pinned deterministic disk image.

## Unresolved gates

Implementation remains blocked until all of these are resolved:

1. **Boot-code provenance.** Identify the exact FreeDOS MBR and FAT partition boot-code fragments used by Rufus, trace them to pinned GPL ms-sys source, extract reproducible binary assets, and add byte-level tests.
2. **Payload provenance.** Extract the minimal files directly from the official FreeDOS 1.4 archive, record individual SHA-256 values, preserve corresponding source and licence material, and prove reproducible extraction.
3. **Kernel configuration.** Rufus sets `FORCELBA` at offset `0x0d` to `0x01`. The implementation must prove this field from FreeDOS source/documentation and reject an unexpected kernel before applying or verifying it.
4. **Filesystem geometry.** Define the exact FAT type, cluster sizing, partition limits, hidden-sector fields, active flag, CHS/LBA compatibility fields, and backup boot-sector behavior.
5. **Structural verification.** Implement an ordinary-file disk-image verifier before any loop-device or physical-media test. It must validate MBR/PBR code, FAT BPB consistency, file entries, file bytes, and boot signatures.
6. **Licensing and maintenance.** Ship notices, corresponding source or a durable source offer as required, upstream archive hashes, extraction tooling, update procedure, and a package-size assessment.
7. **Safety integration.** Reuse the identity, root-disk refusal, lock, cancellation, media-changed reporting, and final readback contracts already established for non-bootable formatting.

## Gate decision

The feasibility gate is **provisionally positive** because no x86 payload execution is required on the ARM64 host and the required media operations can be expressed as deterministic byte and filesystem transformations.

It is **not implementation-green** until boot-code provenance, reproducible payload extraction, kernel configuration, and an ordinary-file verifier are complete. Until then there must be no GTK option, destructive command, package dependency, or release commitment for FreeDOS.

## Primary references

- FreeDOS 1.4 downloads and verification hashes: `https://www.freedos.org/download/` and `https://www.freedos.org/download/verify.txt`
- Rufus FreeDOS extraction implementation: `https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/src/dos.c`
- Rufus FreeDOS payload provenance note: `https://github.com/pbatard/rufus/blob/6d8fbf98305ff37eb531c45cbd6ff44563c53917/res/freedos/readme.txt`
- FreeDOS kernel and SYS documentation: `https://github.com/FDOS/kernel/tree/d6791add2043c9d7b584d840a8ffaf8829fd2bdc`
- FreeCOM source: `https://github.com/FDOS/freecom/tree/04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`
