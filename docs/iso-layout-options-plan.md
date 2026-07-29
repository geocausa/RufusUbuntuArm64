# ISO Image mode layout parity

This tranche expands the bounded Linux ISO Image mode while preserving DD semantics.

Delivered scope:

- MBR or GPT for compatible ARM64 UEFI ISO Image mode;
- UEFI target and FAT32 filesystem remain capability-bound;
- 4, 8, 16, or 32 KiB FAT32 clusters;
- editable FAT32 label with per-image state and reset from stale Windows labels;
- exact binding through confirmation, package-owned privileged helper, diagnostics, result evidence, and settings;
- primary/backup GPT write and readback verification;
- unit tests and real detached/reopened loop-device qualification for MBR and GPT;
- DD mode continues to preserve the source image byte-for-byte and ignores extraction layout controls.

Remaining parity includes separately reviewed Linux NTFS/UEFI:NTFS extraction and any broader target-system/filesystem choices. Physical firmware boot remains tracked in #399.

Refs #289.
