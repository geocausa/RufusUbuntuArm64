# Experimental persistent Linux media creation

The 0.9 development line includes a CLI-only orchestration path that connects the previously reviewed persistence components into one destructive operation.

It is intentionally marked experimental. The graphical application does not expose it, and the privileged GUI launch path rejects the mode even when a caller attempts to supply its flags manually.

## Supported initial contract

The first orchestration scope is deliberately narrow:

- a recognized, raw-bootable Linux ISOHybrid image;
- Ubuntu 20.04 or newer using casper, or Debian using live-boot;
- an architecture-matching fallback UEFI loader in `EFI/BOOT`;
- a fresh GPT partition table;
- one FAT32 EFI System Partition containing a verified writable copy of the ISO tree;
- one ext4 persistence partition using `casper-rw` or `persistence` plus `/ union`;
- files that satisfy FAT32 path, case-collision, and single-file-size limits.

MBR persistence, BIOS/Syslinux-only media, images with files larger than FAT32 can represent, and distro-specific boot layouts outside the bounded detector remain unsupported.

## Destructive sequence

`write --mode linux-persistent --experimental-persistence` performs the following under one whole-disk lock:

1. Opens and identity-binds the selected image and target.
2. Hashes the complete image before mounting it.
3. Mounts the pinned image descriptor read-only in a private workspace.
4. Detects the supported persistence contract and builds a bounded SHA-256 manifest.
5. Calculates a MiB-aligned GPT layout with a FAT32 boot partition and ext4 persistence partition.
6. Rehashes the source and repeats the target safety callback before erasure.
7. Removes stale signatures, writes backup GPT metadata before primary metadata, synchronizes, and verifies both GPT copies plus the protective MBR.
8. Waits for partition nodes whose kernel geometry exactly matches the plan.
9. Formats and privately mounts the FAT32 boot partition.
10. Copies every manifest entry through same-directory temporary files and rehashes the destination.
11. Atomically patches only detector-approved boot configurations and re-runs persistence detection on the writable copy.
12. Unmounts and checks the FAT32 filesystem.
13. Identity-binds, formats, initializes, unmounts, and checks the ext4 persistence partition.
14. Stores a canonical `.rufusarm64/creation.json` record and SHA-256 sidecar in the writable boot tree.
15. Rehashes the source again and flushes target buffers before success.

Cancellation and errors trigger bounded cleanup unmounts. A failure after erasure leaves incomplete media and must be followed by recreating the USB.

## CLI

```bash
sudo rufusarm64-cli write \
  --mode linux-persistent \
  --experimental-persistence \
  --image ubuntu-24.04-arm64.iso \
  --device /dev/sdX \
  --persistence-size 16G \
  --verify
```

A persistence size of `0` uses all aligned capacity remaining after the writable boot partition. The ext4 partition must be at least 1 GiB. The boot partition size is derived from the verified media manifest plus a safety margin.

## Qualification boundary

Automated tests exercise GPT geometry, source and target identity checks, command ordering, symlink refusal, manifest copying, boot-parameter activation, filesystem contracts, cancellation, and ARM64 packaging. They do not prove that every Ubuntu or Debian release boots on every ARM64 firmware.

The mode should remain experimental until a published physical-hardware matrix covers representative Ubuntu and Debian images, multiple USB controllers, 512-byte and 4 KiB logical-sector devices, and supported Snapdragon X firmware. The `qualify start` / reboot / `qualify verify` procedure in `persistence-qualification.md` produces a reproducible evidence bundle for each matrix entry.
