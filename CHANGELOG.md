# Changelog

## 0.8.0 — 2026-07-16

- Added safe preparation of ZIP, gzip, bzip2, XZ, LZMA, and Zstandard-compressed disk images before target erasure.
- Added VHD, VHDX, QCOW2, and VMDK conversion through a pinned source descriptor and `qemu-img`, with rejection of backing files and encrypted images.
- Added decompression-size limits tied to the selected target to stop oversized or malicious archives before destructive work.
- Added lightweight compressed-image previews so compressed Windows ISOs retain Windows layout and filesystem controls in the GUI.
- Added Microsoft Secure Boot DBX download, structural validation, cache management, firmware-DBX inspection, and CLI inspection commands.
- Added PE/COFF Authenticode SHA-256 calculation and checks for direct DBX hash revocations and exact embedded X.509 certificate revocations.
- Added optional pre-write scanning of Windows EFI boot files against a user-selected DBX, with a GUI updater that retrieves architecture-specific data from Microsoft’s official `secureboot_objects` repository.
- Kept FFU explicitly unsupported: official Rufus relies on Windows’ FFU provider and the Linux port does not claim a safe restore path that it cannot implement or verify.

## 0.7.0 — 2026-07-15

- Added true Windows legacy BIOS/CSM media creation for x86 and x86-64 installation ISOs using an active MBR partition, the pinned Windows 7 MBR bootstrap, and BOOTMGR-compatible FAT32 or NTFS partition boot records. Windows ARM64 remains UEFI-only.
- Added a Target system selector for UEFI (non-CSM) or BIOS/UEFI-CSM, with strict compatibility gating: BIOS requires MBR, a root `bootmgr`, and an x86-family Windows ISO.
- Kept manual Automatic/FAT32/NTFS selection and made the selected target system part of the privileged writer command instead of a display-only setting.
- Added optional Windows PE driver auto-loading. A validated driver folder is copied to `USB\drivers`, a marker is written at the media root, and a generated windowsPE RunSynchronous command loads matching `.inf` packages before disk selection. Manual **Load driver** remains available.
- Fixed the 0.6.0 command-line wiring so `--filesystem` and `--driver-folder` are actually passed into the Windows-media engine.
- Restored strict source-image ctime checks and added a SHA-256 snapshot of the already-open source descriptor before destructive work. Raw and Windows writes now reject same-size in-place edits even when modification timestamps are restored.
- Replaced the unsafe symlink fallback from the reviewed 0.6.1 proposal with descriptor-by-descriptor `openat` traversal that rejects symbolic links in every driver-path component on kernels without `openat2`.
- Added aligned `O_DIRECT` verification for block devices with a tested buffered fallback when direct I/O is unsupported.
- Added pinned SHA-256 checks and readback verification for every embedded legacy boot-code fragment, while preserving the generated disk signature, partition table, filesystem BPB, and FAT32 backup boot sector.
- Added x86 unattended-file architecture support, driver-marker verification, source-mutation regression tests, legacy BIOS MBR/PBR tests, ARM64 and x86-64 cross-builds, race tests, shuffled tests, vet, GUI tests, and package integrity checks.
- The erase confirmation now defaults to Cancel, progress is throttled and rate-smoothed, and `inspect --json` returns a non-zero status for unusable images while still emitting parseable JSON.

## 0.6.0 — 2026-07-15

- Added manual **Automatic, FAT32, or NTFS** selection for extracted Windows installation media.
- Kept FAT32 as the firmware-native ARM64 default and retained automatic WIM/ESD splitting for files above FAT32's single-file limit.
- Added GPT and MBR UEFI:NTFS dual-partition layouts for manual or automatically required NTFS media.
- Bundled the pinned Rufus 4.15 1 MiB UEFI:NTFS FAT image, verified its SHA-256 before packaging and again after writing, and used its ARM64/x86 UEFI loaders without modification.
- Added NTFS allocation-unit selection, `mkntfs` formatting, read-only `ntfsfix` checking, and package dependency validation for `ntfs-3g`.
- Added an optional Windows driver-folder chooser that validates `.inf` content and copies the folder to `USB\drivers` for Windows Setup's Load driver dialog.
- Added dual-partition GPT/MBR tests, UEFI:NTFS image integrity/readback tests, filesystem-selection tests, and driver-folder safety tests.
- Kept true legacy-BIOS Windows boot disabled and did not add a misleading DBX updater; both require separate, fully validated implementations.

## 0.5.2 — 2026-07-15

- Corrected the success dialog so skipped copied-file verification is no longer described as full verification.
- Added a visible warning and confirmation-summary note when Windows copied-file verification is disabled.
- Made AppImage-style launches resolve the bundled helper and WIM engine from environment variables and from the helper executable's directory.
- Allowed partition creation to continue when `blockdev --rereadpt` reports a transient refresh failure, as long as the expected partition node appears with the exact geometry.
- Updated portable-build host checks to include `findmnt`, `lsblk`, `fsck.vfat`, and `blockdev`.
- Kept true legacy BIOS Windows boot disabled; current MBR mode remains UEFI-on-MBR only.

## 0.4.0 — 2026-07-15

- Replaced libparted partition creation with a directly validated protective-MBR/GPT writer, avoiding failures caused by an unrelated or stalled host-wide udev queue.
- Added support for copying the current Ubuntu locale and mapped time zone into Windows Setup.
- Hardened local-account validation so command-shell metacharacters cannot enter unattended setup commands.
- Added a responsive, scrollable GTK layout that resizes, maximizes, and remembers its previous window size.
- Added read-only image inspection so the GUI displays the actual partition scheme, target system, and filesystem before writing.
- Added a Windows Setup options dialog with explicit opt-in hardware-check bypass, offline-account support, local administrator creation, reduced initial data collection, and automatic BitLocker provisioning control.
- Added validated `autounattend.xml` generation for ARM64 and x86-64 Windows media, including safe username validation and replacement of conflicting answer files already present in an ISO.
- Added an editable, validated FAT32 volume label.
- Removed the global `udevadm settle` wait that caused successful partition creation to fail when unrelated udev work remained queued.
- Added direct partition-node polling with NVMe/MMC naming support and a bounded `lsblk` fallback.
- Rejected undersized USB drives before expensive WIM splitting whenever the pre-split size estimate is already conclusive.
- Removed redundant WIM integrity-table generation and duplicate full verification passes; split output is validated and then checked after copying with SHA-256.
- Collapsed thousands of WIM progress lines into a single changing progress stage while preserving warnings and final summaries in Details.
- Bundled a verified package-private AArch64 `wimlib-imagex`, with only the standard C runtime required and a system copy retained solely as a fallback.
- Added end-to-end tests for generated Windows answer files, custom labels, WIM progress compaction, answer-file replacement, and removal of the global udev wait.

## 0.3.1 — 2026-07-15

- Replaced the obsolete `policykit-1` package dependency with the actual `pkexec` runtime package.
- Made Ubuntu `wimtools` optional so the application installs when Universe is disabled.
- Improved the Windows-ISO error message when optional WIM support is unavailable.

## 0.3.0 — 2026-07-15

- Bound graphical drive confirmation to a refreshed kernel/device identity to prevent `/dev/sdX` reuse.
- Bound the selected source image to its resolved filesystem device, inode, size, modification time, and change time, and held Windows ISO input through a stable open descriptor.
- Rejected system-critical mounts and active swap even when the underlying disk appears removable.
- Added live block-device ioctl and exact-capacity checks to long-held target descriptors.
- Restricted the Polkit GUI path to safe automatic-mode arguments and removed cached administrator authorization.
- Rejected conflicting/missing Windows installation payloads, invalid split-part sequences, FAT32-invalid names, and case-colliding ISO paths before erasure.
- Made temporary-directory, mount-cleanup, destination-close, partition-notification, and automount-unmount failures observable instead of silently ignoring them.
- Added repeated identity and mount checks before Windows partitioning and formatting commands.
- Added reliable cancellation across `pkexec` and prevented window closure during active writes.
- Rejected arbitrary or damaged files instead of silently raw-writing them.
- Scanned the ISO9660 descriptor sequence rather than assuming the primary descriptor is at sector 16.
- Strengthened MBR and GPT signature validation.
- Removed stale disk signatures before raw-image writing.
- Flushed and invalidated Linux block buffers before raw and Windows verification.
- Moved raw partition-table rereading until after verification.
- Prepared Windows split WIM files before erasing the USB, validated every part, and rejected parts that cannot fit FAT32.
- Verified every numbered split WIM part and supported ISOs that already contain split WIM media.
- Blocked x86-64-only Windows media on ARM64 by default.
- Remounted Windows media read-only for verification and added a final FAT32 filesystem check.
- Removed per-file fsync overhead while retaining a filesystem-wide durability boundary.
- Excluded internal non-removable MMC/eMMC from the normal target policy.
- Corrected package dependencies, command names, man page, build scripts, GUI module packaging, and CI checks.
- Added fake-system integration tests for Windows media creation plus targeted safety, identity, image-inspection, split-image, GUI-command, and package tests.

## 0.2.0 — 2026-07-15

- Added the initial GTK application, Debian package, Polkit helper, and Windows UEFI media workflow.

## 0.1.0 — 2026-07-15

- Added the initial safe raw-image writer.
