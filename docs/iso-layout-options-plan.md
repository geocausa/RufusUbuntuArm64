# ISO Image mode FAT32 layout parity

This document records the completed predecessor tranche that expanded the initial bounded Linux ISO Image mode while preserving DD semantics.

Delivered in that tranche:

- MBR or GPT for compatible ARM64 UEFI ISO Image mode;
- UEFI target and FAT32 filesystem capability bounds;
- 4, 8, 16, or 32 KiB FAT32 clusters;
- editable FAT32 label with per-image state and reset from stale Windows labels;
- exact binding through confirmation, package-owned privileged helper, diagnostics, result evidence, and settings;
- primary/backup GPT write and readback verification;
- unit tests and real detached/reopened loop-device qualification for MBR and GPT; and
- DD mode continuing to preserve the source image byte-for-byte while ignoring extraction layout controls.

The later Linux NTFS/UEFI:NTFS tranche extends this same product surface with Automatic/FAT32/NTFS selection and a shared verified UEFI:NTFS implementation. BIOS/CSM or dual-mode Linux extraction and physical firmware boot qualification remain separate work; physical evidence is tracked in #399.

Refs #289.
