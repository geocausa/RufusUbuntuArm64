# Changelog

## Unreleased

- Added guarded ext2 and ext3 data-only formatting through the existing identity-bound GPT/MBR planner, exact confirmation, read-only e2fsck verification, strict CLI/GTK report contract, and real loop-device qualification.
- Added application-scoped System, Light, and Dark appearance selection with canonical persisted settings and safe restoration of the startup desktop preference.
- Completed bounded main-window option/action tooltips while preserving workflow-specific disclosures.
- Added a standard GNU gettext runtime, deterministic primary-interface POT, safe English fallback, and exact post-composition translation for reviewed static main-window, tooltip, appearance, and accessibility text while keeping machine and destructive-operation contracts byte-stable.

## 0.14.0 — 2026-07-26

- Added descriptor-bound drive backup in raw, dynamic VHD, dynamic VHDX, and mounted-filesystem ISO/UDF formats, with exact source identity, conservative destination admission, cancellation, hashing, independent content comparison, and atomic no-replace publication.
- Added a guarded experimental single-store-v1 FFU restore path with strict descriptor planning, authenticated catalog/integrity evidence, publisher authorization, target-bound destructive confirmation, exclusive acquisition, ordered writes, complete content verification, and explicit unsupported-profile refusal.
- Added GTK integration for FFU review/restore, physical-qualification evidence, drive-backup format selection, filesystem ISO/UDF capture, and reusable identity-bound USB qualification report export.
- Added bounded, authenticated progress for compressed image preparation and fixed completion so 100% is reported only after the complete container has passed source identity and digest verification.
- Added bounded read-only El Torito UEFI extraction and strengthened Windows 11 setup Quality of Life selection without broadening automatic or unsupported media paths.
- Added real privileged loop qualification for raw/VHD/VHDX/ISO-UDF backup and FFU software paths, native ARM64 execution, Go 1.22 compatibility, static/vulnerability checks, and byte-for-byte reproducible Debian packaging on the exact release candidate.
- Kept FFU restore experimental, FFU capture unimplemented, Windows To Go deferred, the production acquisition channel disabled, the package-owned UEFI integrity loader unsigned, and universal physical boot, Secure Boot, media-health, and vendor-device compatibility explicitly unclaimed.

## 0.13.0 — 2026-07-20

- Added a guarded **Restore / format…** workflow for GPT or MBR data-only media using FAT32, exFAT, NTFS, or ext4, with identity-bound planning, exact FORMAT confirmation, cancellation, filesystem checks, and conservative incomplete-media reporting.
- Added deterministic FreeDOS 1.4 media creation from checksum-pinned, source-retained FreeDOS and FreeCOM payloads, with complete MBR/FAT32 verification, real loop-device qualification, terminal and GTK workflows, and an explicit x86 BIOS/UEFI-Legacy-only boundary.
- Added explicit post-operation actions to create another USB from the retained image or restore the exact completed/failed target to ordinary storage through the existing guarded formatter.
- Added bounded read-only Linux compatibility reporting for hybrid disk layouts, optical-only ISOs, validated El Torito BIOS/UEFI entries, and ISOLINUX/SYSLINUX/GRUB fingerprints without mounting or executing image content.
- Exposed the existing threshold-signed/local-signed acquisition stack in the composed GTK application, enabled SHA-bound resumable partials, retained safe cancellation and storage preflight, and kept the production built-in channel disabled pending public offline-signing and mirror operations.
- Added GTK keyboard mnemonics, safe visible accelerators, assistive-technology names/descriptions, and selectable compatibility and operation-detail text without binding shortcuts directly to erasure or cancellation.
- Strengthened Windows setup analysis with bounded multi-edition metadata and WIM, ESD, or validated split-SWM payload reporting, while rejecting conflicting edition classes, payload families, part sequences, and inconsistent graphical reports.
- Reduced ordinary Windows-media source verification from three complete ISO hashes to one authenticated pass when Linux can hold the selected ISO under a read lease; unsupported or already-writable sources retain the original conservative three-pass comparison.
- Reduced persistent Linux source verification from three complete image hashes to one authenticated pass under the same identity-bound Linux read lease, while retaining manifest-bound copy verification and the conservative three-pass fallback.
- Changed optional raw-image verification to hash only the physical target and compare it with the SHA-256 authenticated during the completed write, removing a redundant third complete source read.
- Reduced sequential compressed-image preparation to one lease-held container read that authenticates while decompressing, removed the post-preparation container rehash on held ZIP/virtual inputs, and passed package-owned expanded digests to the raw writer so private prepared images are read only once during target writing.
- Held plain raw/ISOHybrid sources under the identity-bound Linux read lease through destructive writing, while retaining the complete pre-write and write-time digest comparison and the conservative fallback for unsupported or already-writable sources.
- Aligned fresh-profile defaults with pinned upstream Rufus: post-write verification is opt-in, quick format remains on, bad-block testing and persistence remain off, and Windows partition/target choices now default to image-derived Automatic rather than preselecting GPT/UEFI.
- Recognized proven BIOS-only Windows setup ISOs by binding root `bootmgr` to bounded `boot.wim` x86/x64 metadata, allowing Automatic to choose MBR/BIOS without weakening ARM64 UEFI checks.
- Fixed the FreeDOS GTK progress guard to validate the helper against the reviewed required-extent write/readback totals instead of the obsolete whole-device total.
- Preserved every existing source/target identity, privilege, destructive confirmation, cancellation, verification, reproducibility, and native ARM64 gate. Physical hardware boot and persistence qualification remain separate release evidence.

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
- Added a reproducibly built, source-retained ARM64 `uefi-md5sum` loader with transactional installation, rollback, and QEMU chainload qualification.
- Added a graphical UEFI validation workflow for mounted or extracted media directories.
- Kept the package-owned validation loader unsigned and Secure Boot compatibility explicitly unestablished.

## 0.10.6 — 2026-07-17

- Added a complete Linux persistence workflow with guarded GPT/UEFI creation for supported Ubuntu casper and Debian live-boot media.
- Added identity-bound graphical persistence planning, exact confirmation, cancellation, source hashing, verified writable-tree copy, and deterministic creation records.
- Added first-boot and reboot qualification commands with checksum-backed evidence and explicit hardware/firmware scope.

## 0.10.5 — 2026-07-16

- Added threshold-signed and local-signed image acquisition metadata, rollback and expiry checks, bounded HTTPS redirects, verified resumable downloads, and owner-private partials.
- Added graphical acquisition with storage preflight, cancellation, and atomic installation only after signed size and SHA-256 verification.
- Kept the production built-in acquisition channel disabled pending offline-root provisioning and public mirror operations.

## 0.10.4 — 2026-07-15

- Added GTK keyboard navigation, assistive names and descriptions, selectable diagnostics, remembered window size, and safe visible shortcuts.
- Added deterministic exportable operation diagnostics and bounded image compatibility reporting.

## 0.10.3 — 2026-07-14

- Added x86 and x86-64 Windows BIOS/CSM media creation with validated `bootmgr`, MBR/PBR boot code, and source-retained ms-sys attribution.
- Added validated Windows PE driver-folder staging and automatic setup loading.

## 0.10.2 — 2026-07-13

- Added compressed ZIP/gzip/bzip2/XZ/LZMA/Zstandard and VHD/VHDX/QCOW2/VMDK preparation with target-sized expansion bounds.
- Added Microsoft Secure Boot DBX inspection and architecture-aware EFI revocation checks.

## 0.10.1 — 2026-07-12

- Added manual Automatic/FAT32/NTFS selection, verified UEFI:NTFS boot support, and FAT32/NTFS post-write checks.
- Added optional Windows driver-folder staging and strengthened source/target verification.

## 0.10.0 — 2026-07-11

- Added the resizable GTK application, Windows setup customization, detected layout display, editable volume labels, and bundled AArch64 WIM support.
- Added stricter image recognition, stronger MBR/GPT validation, guarded cancellation, and source/target identity binding.

## 0.1.0 — 2026-07-10

- Added the initial safe raw writer with whole-disk enumeration, system-disk refusal, synchronous writes, and optional verification.
