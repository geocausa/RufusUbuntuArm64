# Changelog

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
