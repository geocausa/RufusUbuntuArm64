# RufusArm64 0.9.0

RufusArm64 0.9.0 is the first public parity-development release after the recovered 0.8.0 source baseline. It focuses on product diagnostics, authenticated acquisition, and a carefully gated Linux persistence implementation.

## Highlights

- Rich progress, rate and ETA reporting with exportable timestamped diagnostics.
- Ed25519-signed acquisition catalogs and checksum-gated atomic downloads.
- Ubuntu casper and Debian live-boot persistence detection and planning.
- Verified writable Linux media-tree copying with FAT32 compatibility checks.
- CLI-only experimental GPT/UEFI persistence creation with FAT32 boot media and ext4 persistence.
- Backup-first durable GPT writes, exact metadata readback, inherited-descriptor filesystem operations, and strict source/target identity checks.

## Experimental persistence boundary

Persistence creation must be requested explicitly with `--mode linux-persistent --experimental-persistence`. It is not available from the graphical privileged path. It currently requires supported Ubuntu or Debian GPT/UEFI media and remains subject to physical ARM64 boot qualification. A failed operation after erasure leaves incomplete media and is never reported as recoverable success.

## Remaining parity work

Windows To Go, FreeDOS creation, a built-in remote ISO catalog and picker, FFU restoration, full Authenticode signer-chain construction, broader Syslinux/GRUB workarounds, translations, and a wider physical-hardware matrix remain future work.
