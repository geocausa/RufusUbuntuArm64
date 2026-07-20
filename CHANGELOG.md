# Changelog

## 0.12.1 — 2026-07-20

- Fixed the packaged graphical launcher so GTK 3 is selected before any integrated dialog imports `Gtk`, preventing silent startup failure on systems that also provide GTK 4 introspection.
- Added a regression that executes the exact isolated launcher payload and requires the GTK 3 version pin to occur before the integrated dialog import.
- Kept the Stage 1 feature set unchanged; this is a focused field-reported startup patch over 0.12.0.

## 0.12.0 — 2026-07-19

- Added an identity-bound, read-only drive-to-image command and graphical **Save drive image…** workflow with destination planning, exact confirmation, progress, cancellation, SHA-256 reporting, atomic no-replace publication, and desktop-user ownership handoff.
- Completed a focused Stage 1 code audit covering privilege boundaries, process lifecycle, report validation, package isolation, and release automation.
- Refused graphical destinations unless the authenticated desktop user can create files in the held directory, preventing administrator authentication from becoming an arbitrary privileged file-creation service.
- Made progress-channel failures cancel before publication and made exceptional GTK paths terminate, drain, escalate, and reap only their owned process group before releasing the application busy state.
- Tightened schema validation so successful reports cannot contain failures, failed or cancelled reports require complete failure records, numeric fields remain exact integers, and GUI success requires matching exit status, size, regular-file type, and desktop ownership.
- Preserved the unsigned UEFI runtime-integrity boundary: Secure Boot compatibility is not established, and physical hardware qualification remains separate from software and QEMU gates.

## 0.11.0 — 2026-07-18

- Added a descriptor-rooted, bounded UEFI media analyzer for fallback-loader architecture, PE/COFF structure, DBX revocations, SBAT metadata, trusted local or firmware SBAT levels, and structured CLI/GTK reporting.
- Added Rufus-compatible `md5sum.txt` generation and verification plus an opt-in boot-time ARM64 media-integrity option for the guarded Ubuntu/Debian persistent writable-copy path.
- Reproducibly built the package-private `uefi-md5sum` v1.2 ARM64 loader from exact upstream and EDK2 commits, retained corresponding source and provenance, and kept the loader explicitly unsigned.
- Added transactional fallback-loader wrapping and rollback, exact post-install manifest verification, qualification-record hashes, guarded GUI disclosure, and refusal in raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers.
- Qualified unchanged and intentionally corrupted GPT/FAT32 media under pinned AArch64 QEMU firmware, including original-loader chainload and complete serial, image, firmware, provenance, and checksum evidence.
- Kept Secure Boot compatibility and universal hardware compatibility explicitly unclaimed; physical Surface Pro 11 boot and persistence start/reboot/verify evidence remains a separate per-hardware qualification gate.
- Hardened tagged releases so the ARM64 package, deterministic project source, pinned WIM source, and deterministic `uefi-md5sum` corresponding source are produced from one synchronized version contract.

## 0.10.6 — 2026-07-17

- Marked both fresh persistent-live GPT partitions with attribute bit 63 before the kernel publishes them, preventing desktop automount services from racing FAT32 and ext4 creation.
- Included the do-not-automount attribute in exact primary and backup GPT entry-table readback verification and added focused regression coverage for both partitions.
- Bumped the Debian package and runtime version so systems already on 0.10.5 receive the correction through a normal upgrade.

## 0.10.5 — 2026-07-17

- Completed the pre-parity correctness, destructive-operation, privilege-boundary, parser, arithmetic, concurrency, acquisition, packaging, and supply-chain audit.
- Retained confirmed source and target identities through destructive revalidation, added checked size and offset arithmetic, and strengthened GPT durability, short-write handling, and exact metadata readback.
- Bound reused verified downloads to no-follow regular-file descriptors and closed pathname replacement and symbolic-link races.
- Moved slow image, device, and signed-catalog probes off the GTK thread; added stale-result generations, worker-owned process references, and early cancellation handling.
- Added Go 1.22 compatibility, Staticcheck, Govulncheck, Actionlint, ShellCheck, Lintian, AppStream, desktop validation, deterministic packaging, and byte-for-byte package reproducibility gates.
- Corrected Debian metadata, runtime dependencies, copyright, changelog, launcher man pages, and verification wording. Software checks do not claim firmware boot, Secure Boot acceptance, or persistence across reboot without physical qualification.
- Fixed real-device persistent-media creation by retaining identity-bound, flocked partition descriptors without a kernel-exclusive open, so FAT32/ext4 formatters and filesystem tools can safely reopen inherited `/proc/self/fd/N` targets; added a real loop-device regression gate.

## 0.10.4 — 2026-07-17

- Fixed persistence analysis for the official Ubuntu 26.04 ARM64 desktop ISO root alias `ubuntu -> .`.
- Omitted only direct root-self aliases that cannot be represented on FAT32 and would otherwise recursively duplicate the complete media tree.
- Kept nested links back to the media root, host-path escapes, absolute escapes, cycles, special nodes, and unbounded traversal strictly refused.
- Added regression coverage for analysis, verified copying, omission accounting, and preservation of the ordinary casper payload.

## 0.10.3 — 2026-07-17

- Consolidated the desktop experience to one visible **RufusArm64** application entry.
- Added a **Create Persistent Live USB** desktop action to that single launcher.
- Kept the persistence wizard and its narrow privileged helper installed internally while hiding the implementation-only secondary menu entry.
- Preserved the ordinary writer and persistent writer as distinct guarded workflows without presenting them as duplicate applications.

## 0.10.2 — 2026-07-17

- Fixed persistence analysis for official Canonical live images that contain in-tree directory symbolic links such as `dists/stable`.
- Materialized accepted directory links as real FAT32 directories and included all duplicated files in entry, byte, and capacity limits.
- Retained strict refusal of absolute or escaping links, symbolic-link cycles, device nodes, unsupported targets, FAT32 collisions, and unbounded trees.
- Added end-to-end tests that analyze, copy, hash, and verify a distribution directory exposed through a relative directory link.
- Kept the ordinary raw/ISOHybrid writer byte-for-byte unchanged; this release repairs only the guarded persistent-live workflow.

## 0.10.1 — 2026-07-16

- Aligned graphical persistence analysis with the actual fresh GPT/FAT32/ext4 creator instead of extending or validating the ISO's embedded hybrid partition table.
- Fixed compatibility analysis for Canonical Resolute ARM64/X1E concept images whose ISOHybrid MBR contains embedded boot-image mappings that are irrelevant to the writable target layout.
- Made mandatory analysis perform the same full media-tree, fallback UEFI loader, FAT32 safety, boot-capacity, and requested persistence-size checks used by creation.
- Preserved strict read-only source mounting, identity pinning, cancellation cleanup, and pre-destructive target revalidation.
- Added regression tests proving analysis returns the creator's GPT partition 1 boot layout and partition 2 ext4 persistence contract on both x86-64 and native ARM64 CI.

## 0.10.0 — 2026-07-16

- Added a graphical verified-image downloader and read-only Linux persistence compatibility planner.
- Added automatic identity-bound, private read-only ISO mounting for graphical persistence analysis, with visible elapsed-time progress and complete cleanup.
- Added a dedicated persistent-live-media wizard with mandatory read-only analysis, pre-authentication source and target identity binding, a separate strict Polkit helper, safe cancellation, and post-creation reboot qualification instructions.
- Added modern Ubuntu casper detection and boot patching for `/casper/vmlinuz $cmdline` layouts while retaining strict metadata, path, and symlink safety gates.
- Added a built-in acquisition-channel trust core with canonical metadata, threshold Ed25519 root and catalog roles, dual-authorized root rotation, monotonic rollback protection, expiry/freeze checks, versioned multi-root catch-up, sequential cached root history, clock-rollback detection, and owner-only atomic state.
- Made the graphical downloader prefer the built-in verified channel while preserving local signed-catalog files as an advanced recovery path.
- Kept production channel activation disabled until offline root keys and the first reviewed catalog are provisioned; no private signing key is included in source, CI, packages, or artifacts.
- Added a source-only offline channel-administration toolkit for public-key IDs, canonical signing payloads, detached-signature assembly, sequential chain verification, production configuration validation, and deterministic atomic publication directories; it has no private-key input or signing implementation.
- Strengthened package tests so the installed GUI, dedicated persistence helper, desktop entry, documentation, and Debian control version are verified from the built artifact.

## 0.9.0 — 2026-07-16

- Added richer graphical progress with byte counts, transfer rates, ETA, timestamped diagnostics, and copy/save/clear report controls.
- Added strict Ed25519-signed acquisition catalogs and HTTPS-only, redirect-constrained, size-bounded, SHA-256-verified atomic image downloads through the CLI.
- Added read-only Ubuntu casper and Debian live-boot persistence detection, boot-parameter analysis, and append-only MBR/GPT planning.
- Added identity-bound persistence materialization primitives for exact GPT/MBR updates, symlink-resistant boot-file patching, and verified ext4 initialization.
- Added a bounded SHA-256 media-tree manifest and FAT32-safe verified copy engine for writable Linux boot media.
- Added an explicit CLI-only experimental GPT/UEFI persistent-Linux writer that retains the whole-disk lock, verifies source and target identities, copies and rehashes the media tree, patches approved boot configurations, and checks FAT32 and ext4 filesystems.
- Hardened persistence creation with backup-first durable GPT installation, exact metadata readback, 4 KiB FAT32 clusters, conservative allocation sizing, inherited-descriptor formatting/checking, and exact kernel partition geometry and parent-disk validation.
- Kept the experimental persistence writer unavailable to the graphical privileged path pending physical ARM64 boot qualification.
- Added a canonical repository `VERSION` file and release/CI checks so runtime, package, documentation, metadata, tag, and artifact versions cannot silently drift.

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
