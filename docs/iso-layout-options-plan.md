# ISO Image mode layout parity

This branch expands the bounded Linux ISO Image mode beyond its initial fixed MBR/FAT32 layout while keeping DD Image mode immutable.

Planned exact scope:

- MBR or GPT for compatible ARM64 UEFI ISO Image mode;
- UEFI target fixed by validated media architecture;
- FAT32 filesystem with reviewed cluster sizes;
- editable FAT32 volume label reset when the selected image changes;
- exact option binding through confirmation, privileged helper, diagnostics, tests, and loop-device qualification;
- DD mode continues to preserve the source image byte-for-byte and ignores ISO extraction layout choices.

Refs #289.
