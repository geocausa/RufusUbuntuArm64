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
- Strict local signed catalog, threshold-root built-in channel, rollback-protected metadata cache, graphical acquisition workflow, and source-only offline public-metadata administration toolkit (implemented; production offline-key ceremony and publication pending)
- Linux persistence planner, verified writable-tree copy, guarded GPT/UEFI creator, dedicated identity-bound graphical wizard, and checksum-backed reboot qualification reports (implemented; physical ARM64 qualification matrix pending)
- FreeDOS creation
- Windows To Go feasibility and implementation
- Production offline-root provisioning, published signed catalog, download resumption, and mirror operations
- Broader Syslinux/GRUB compatibility workarounds

## 0.11 — UEFI analysis and runtime media integrity (completed)

- Descriptor-rooted fallback-loader, PE/COFF, DBX, SBAT, and firmware-policy analysis with CLI and GTK reporting
- Rufus-compatible `md5sum.txt` generation, parsing, and full-tree verification
- Reproducibly built, source-retained ARM64 `uefi-md5sum` loader with transactional installation and rollback
- Guarded persistent-writer and GUI integration with explicit unsigned disclosure and unsupported-mode refusal
- Pinned AArch64 QEMU success, corruption, and original-loader chainload qualification
- Physical Surface Pro 11 and broader hardware qualification remains tracked under 0.5

## 0.12 — Stage 1 guarded backup and product completion (completed)

- Identity-bound command and GTK workflow for read-only removable-drive image capture
- Exact destination planning and confirmation, progress, cancellation, SHA-256, atomic publication, and desktop ownership
- Focused privilege, process-lifecycle, report-schema, launcher-isolation, native ARM64, and reproducible-package audit
- Clean Stage 1 release package and rollback documentation; physical play-testing continues as field feedback

## 1.0 — supportable stable release

- Signed release artifacts
- Reproducible-build documentation
- Hardware compatibility matrix
- Independent review of privileged operations
