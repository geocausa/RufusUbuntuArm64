# Roadmap

## 0.1 — safe raw writer (completed)

- Whole-disk enumeration
- System-disk refusal
- Raw write, sync, and verification

## 0.2 — graphical Ubuntu ARM64 application (completed)

- GTK interface and `.deb` package
- Polkit privilege separation
- Windows UEFI ISO preparation

## 0.3 — full code-hardening pass (completed)

- Device-identity binding and repeated destructive-command checks
- Reliable GUI cancellation and active-write close protection
- Strict image recognition and stronger MBR/GPT inspection
- Prevalidated WIM splitting and post-copy verification
- Cache-flushed verification and FAT32 filesystem checking

## 0.4 — Windows experience and usability (completed)

- Resizable, scrollable interface with remembered window size
- Detected layout display and editable volume label
- Windows Setup customization dialog and validated answer-file generation
- Early USB-capacity rejection and faster WIM preparation
- Compact WIM progress reporting
- Direct partition detection without a global udev-queue dependency
- Verified bundled AArch64 WIM engine with system fallback

## 0.5 — hardware qualification (in progress)

- Surface Pro 11 X1E Windows and Linux USB boot tests
- Additional Snapdragon X Elite systems
- Multiple USB controllers, flash sizes, and failure-injection tests

## 0.6 — Windows filesystem and firmware compatibility (completed)

- Manual Automatic/FAT32/NTFS selection
- Verified ARM64/x86 UEFI:NTFS boot partition
- Optional Windows driver-folder staging
- FAT32 and NTFS post-write checks

## 0.7 — Windows BIOS and driver integration (completed)

- True x86/x86-64 Windows BIOS/CSM MBR and PBR support
- Secure driver-folder traversal and Windows PE driver auto-loading
- Source hashing and pinned legacy boot assets

## 0.8 — compressed, virtual-disk, and DBX support (completed)

- ZIP, gzip, bzip2, XZ, LZMA, and Zstandard image preparation
- VHD, VHDX, QCOW2, and VMDK conversion with backing/encryption refusal
- Microsoft DBX cache updates and EFI direct-hash/certificate checks
- Target-sized preparation limits and compressed-image previews

## 0.9 — parity and product-quality programme (in progress)

- Rich progress and exportable diagnostics (completed)
- Strict Ed25519-signed acquisition catalog and checksum-gated download core (completed foundation; remote catalog/UI pending)
- Linux persistence planner, verified writable-tree copy, CLI-only experimental GPT/UEFI orchestration, and checksum-backed reboot qualification reports (implemented; physical ARM64 matrix and GUI stabilization pending)
- FreeDOS creation
- Windows To Go feasibility and implementation
- Authenticated remote catalog distribution, resumption, and graphical acquisition workflow
- Broader Syslinux/GRUB compatibility workarounds

## 1.0 — supportable stable release

- Signed release artifacts
- Reproducible-build documentation
- Hardware compatibility matrix
- Independent review of privileged operations
