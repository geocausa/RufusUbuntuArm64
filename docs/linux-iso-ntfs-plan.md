# Linux ISO Image mode NTFS / UEFI:NTFS tranche

## Purpose

Extend the bounded Linux ISO Image mode beyond FAT32 without weakening its source, target, verification, or DD-mode safety contracts.

The repository already packages Rufus 4.15's pinned 1 MiB multi-architecture UEFI:NTFS FAT image and uses it for Windows installation media. This tranche must reuse that exact verified asset and one shared implementation rather than creating a Linux-only copy of the boot path.

## Exact product boundary

For compatible ARM64 UEFI Linux ISOHybrid media:

- expose **Automatic**, **FAT32**, or **NTFS** in ISO Image mode;
- keep **DD Image mode** image-derived and unaffected;
- keep the target system fixed to validated UEFI;
- support reviewed MBR and GPT layouts;
- use one NTFS data partition plus the verified UEFI:NTFS boot partition for NTFS media;
- retain the required native ARM64 fallback loader inside the extracted media tree;
- retain editable per-image volume labels and reviewed cluster-size choices;
- do not combine NTFS ISO Image mode with persistence in this tranche.

Automatic selection should prefer FAT32 when the complete inspected tree is representable. It may select NTFS only when the FAT32 path is incompatible and every NTFS/UEFI:NTFS requirement passes before erasure.

## Shared implementation requirement

Create a package-private shared UEFI:NTFS component used by both Windows and Linux media paths for:

- package/development asset discovery;
- exact 1 MiB size and SHA-256 verification;
- MBR and GPT two-partition planning;
- protective/primary/backup metadata construction and readback;
- boot-image writing to the held target descriptor;
- complete boot-partition image comparison after partition-table reread.

The Windows path must retain its existing behaviour and tests after the refactor.

## Linux NTFS inspection and copy policy

Before the destructive boundary, the Linux path must:

- bind and authenticate the exact source and target as today;
- inventory and hash the complete media tree;
- require the architecture-specific native fallback UEFI loader;
- reject traversal, escaping symlinks, cycles, unsupported entries, and target-hostile names;
- enforce NTFS case-insensitive path uniqueness and reserved-name rules;
- calculate data- and boot-partition capacity, including formatting margin;
- require the package-owned NTFS formatter, repair-free consistency checker, and verified UEFI:NTFS image;
- refuse unsupported logical-sector, cluster, or partition geometry before erasure.

After erasure it must format through the held/revalidated target path, copy transactionally, hash every copied file back, check NTFS without silently repairing it, compare the UEFI:NTFS partition against the pinned image, flush the physical target, and report the exact scheme/filesystem/cluster/boot-asset evidence.

## Qualification

Required software evidence:

- unit tests for FAT32-versus-NTFS automatic selection and refusal reasons;
- asset missing, altered, wrong-size, and wrong-target refusal tests;
- MBR and GPT metadata/readback tests;
- real detached-and-reopened loop-device qualification for FAT32, MBR/NTFS, and GPT/NTFS;
- cancellation and source/target identity-change evidence;
- Windows-media regression tests proving the shared refactor is behaviour-preserving;
- Go 1.22, native ARM64, static/vulnerability audit, privileged loop invariants, and reproducible Debian packaging.

Physical ARM64 firmware boot remains separate qualification under #399 and is not inferred from loop tests.

## Deliberately outside this tranche

- persistence on NTFS media;
- BIOS/CSM Linux extraction;
- exFAT, UDF, ext-family, or ReFS ISO Image mode;
- RISC-V64 qualification;
- any claim that software-loop success proves Surface or other firmware boot.

Refs #289.
Refs #399.
