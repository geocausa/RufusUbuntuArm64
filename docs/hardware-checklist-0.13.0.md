# RufusArm64 0.13.0 real-machine sanity record

This is the human publication record for RufusArm64 0.13.0. It records observations on the tested ARM64 environment and does not create universal hardware, Secure Boot, whole-device-health, or legacy-PC compatibility claims.

## Release-candidate boundary

- Stage 2 merge commit before final release metadata: `75e12a69d8b835a47962b374c83945b8f4ae0254`.
- Corrected hardware-test source: `ce41ba8b467fccd12dc129db6d51ee2512291cd7`.
- Hardware-test prerelease: `v0.13.0-pr265-test`.
- Hardware-test package: `rufusarm64_0.13.0+pr265.ce41ba8b_arm64.deb`.
- Hardware-test package SHA-256: `4517001008edb99dd520560179f9e2ab524d210af2f0a1a21f6eebc17d15d91b`.
- The clean `rufusarm64_0.13.0_arm64.deb` checksum and source archives are recorded by the immutable tag release workflow and published beside the package.

## Recorded real-hardware evidence

### Package and GTK interface

- [x] The ARM64 Debian package installs and opens the GTK 3 application.
- [x] Source selection, target selection, warnings, destructive confirmation, progress, cancellation, completion, and Close controls were visible and usable.
- [x] High-DPI operation was observed at 2880×1920 with 200% scaling, an effective 1440×960 work area.
- [x] Report-heavy dialogs remained usable and scrollable.
- [ ] Exact 1280×800 hardware was not available; the effective work area was larger. Automated layout contracts cover 800p visibility and no field failure was observed.

### Linux and persistence

- [x] Ubuntu ARM64 media creation completed and the produced USB booted on the intended ARM64 machine.
- [x] Persistent Ubuntu media was created and booted.
- [x] A harmless saved change survived shutdown and reboot on the same USB and machine.
- [x] Later persistence-path changes were limited to source-file read holding and redundant-hash reduction; persistence layout, copied-media manifest verification, boot configuration, and retention behaviour were preserved.
- [x] Secure Boot compatibility is not claimed for the unsigned optional runtime-integrity loader.

### Windows ARM64 media

- [x] Windows ARM64 installation-media creation completed on the ARM64 host.
- [x] ARM64 media remained GPT/UEFI-only and BIOS/CSM was not offered for ARM64 images.
- [x] Windows setup payload analysis and guarded options were exercised.
- [x] No Windows To Go, FFU restoration, or universal installation-success claim is made.

### Data-only restore and reuse

- [x] Non-bootable FAT32 media creation completed and verified on real removable media.
- [x] GPT/MBR FAT32, exFAT, NTFS, and ext4 formatter paths passed real loop-device qualification in CI.
- [x] The product does not label data-only media as bootable.

### FreeDOS 1.4

- [x] The GTK plan disclosed x86-only BIOS/UEFI-Legacy scope and required the exact destructive phrase.
- [x] A 29.2 GiB Lexar JumpDrive was created using required-extent I/O rather than whole-device overwrite.
- [x] Final report status: `succeeded`; `verified: true`; `reusable: true`.
- [x] Bytes written: `17,989,632`.
- [x] Bytes read back and verified: `17,989,632`.
- [x] Verification scope: `required-filesystem-extents`.
- [x] Extent-set SHA-256: `41d6180cc0a53c79cabf28c39314b8daa0f26f926503c32f75a498436c4dc262`.
- [x] The resulting partition remains nearly full-size while untouched unallocated clusters are not represented as tested.
- [x] The report does not claim whole-device health and points exhaustive testing to **Check USB**.
- [ ] Physical FreeDOS boot was not tested because no x86 BIOS/Legacy or UEFI-CSM machine was available.
- [x] Legacy boot is explicitly deferred to community feedback and is not recorded as passed.

## Software and delivery gates

- [x] Go 1.22 full suite.
- [x] Native ARM64 complete suite and packaged-binary execution.
- [x] Static, workflow, and vulnerability audits.
- [x] Privileged loop-device invariants.
- [x] FreeDOS real-loop qualification.
- [x] GPT/MBR formatter real-loop qualification.
- [x] Bundled WIM engine build.
- [x] Deterministic ARM64 UEFI loader reproduction.
- [x] Full ARM64 Debian package pass and byte-for-byte reproducibility.
- [x] Production acquisition remains disabled; no unsigned bypass or private signing key is shipped.

## Publication decision

- [x] No unresolved defect can select, erase, publish, or qualify the wrong source or target.
- [x] No release text claims whole-device FreeDOS qualification from required-extent verification.
- [x] No release text claims Secure Boot compatibility for the unsigned runtime-integrity loader.
- [x] No release text claims universal physical boot success.
- [x] The unavailable FreeDOS legacy boot test is disclosed as untested and deferred, not silently converted into a pass.

## Signed-off result

- Decision: **GO**, within the documented support boundaries above.
- Date: 2026-07-23.
- Tester/maintainer: geocausa.
- Host class: Ubuntu ARM64 system; high-DPI 2880×1920 display at 200% scaling.
- Release-candidate branch: `release/0.13.0-final` from Stage 2 commit `75e12a69d8b835a47962b374c83945b8f4ae0254`.
- Final package SHA-256: published by the successful immutable `v0.13.0` release workflow.
- Evidence: Stage 2 issue #118, release programme #8, FreeDOS defect/fix #264/#265, and exact-head CI run 30033320147.
- Notes: Future community reports may add specific x86 BIOS/Legacy boot evidence without changing the bounded 0.13.0 claims.
