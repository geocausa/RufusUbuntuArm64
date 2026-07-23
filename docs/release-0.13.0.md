# RufusArm64 0.13.0

## Highlights

RufusArm64 0.13.0 is the Stage 2 practical-parity release candidate for Ubuntu ARM64.

- **Restore / format…** creates verified ordinary data storage through a separate identity-bound formatter supporting GPT or MBR and FAT32, exFAT, NTFS, or ext4.
- **FreeDOS…** creates a deterministic, checksum-pinned FreeDOS 1.4 layout through bounded quick-format-style writes and required-extent readback. It retains a nearly full-size FAT32 partition and targets x86 BIOS or UEFI Legacy/CSM computers only.
- Main-writer completion now offers explicit **Create another USB** and **Restore drive for storage…** actions without erasing anything automatically.
- Linux raw/ISO inspection distinguishes hybrid media from optical-only ISOs, validates El Torito BIOS/UEFI entries, and reports ISOLINUX, SYSLINUX, and GRUB fingerprints when present in referenced boot images.
- Verified image acquisition is exposed in the composed GTK application with cancellation, storage preflight, signed size/SHA-256 installation, and SHA-bound resumable private partials.
- Keyboard mnemonics, safe visible shortcuts, assistive-technology metadata, and selectable compatibility/status text improve non-mouse use.
- Report-heavy GTK dialogs keep confirmation, progress, action, and Close controls visible on 800p displays while long details and reports remain scrollable.
- Windows setup analysis reports bounded edition names/count plus WIM, ESD, or validated split-SWM payload type and part count before optional customizations are enabled.

The existing ordinary raw, compressed, virtual-disk, Windows, persistence, UEFI, backup, qualification, cancellation, identity, and verification paths remain in place.

## Safety and support boundaries

Every write, restore/format, FreeDOS creation, qualification, or persistent-media operation can destroy all accessible data on the selected target. Confirm the device path, model, capacity, and generated phrase before authentication.

Software verification is not physical boot qualification. The deterministic FreeDOS workflow proves the reviewed final MBR/FAT32 boot and filesystem extents were written and read back; it deliberately does not overwrite or qualify unallocated data clusters. Use **Check USB** for exhaustive whole-device testing. Neither result proves that a particular x86 BIOS/Legacy computer will boot the media.

FreeDOS media is not for ARM64 or UEFI-only computers. Windows ARM64 media remains UEFI-only. Windows To Go, FFU restoration, encrypted persistence, and arbitrary bootloader replacement remain unsupported.

The package-owned ARM64 `uefi-md5sum` loader remains unsigned. **Secure Boot compatibility is not established** for that optional persistent-media wrapper. DBX and SBAT inspection is read-only and does not modify firmware.

The production built-in acquisition channel remains disabled until reviewed public mirrors, offline root-key operations, and a signed catalogue are provisioned. The separately trusted local signed-catalogue recovery workflow remains available. No private signing key is included in the repository, CI, package, or release artifacts.

Physical hardware testing remains a mandatory publication gate. Complete `docs/hardware-checklist-0.13.0.md` on the intended ARM64 system and retain the resulting diagnostic and qualification evidence before publishing this candidate as a supported release.

## Verification before publication

The release candidate must pass the complete repository CI, native ARM64, reproducible Debian package, loop-device formatter, FreeDOS loop, WIM/UEFI, static-analysis, Lintian, AppStream, desktop, and package-content gates at the exact release-candidate commit.

Then complete the human checklist with at least:

- ordinary Linux image creation and boot observation;
- Windows ARM64 media creation and firmware boot observation;
- one persistent Ubuntu or Debian start/reboot/verify record when persistence is claimed;
- data-only restore/format and ordinary file reuse;
- one FreeDOS creation on a normal-capacity USB confirming that progress and runtime scale with the displayed required extent totals rather than twice the device capacity;
- explicit confirmation that the FreeDOS report claims required-extent verification only and directs exhaustive testing to **Check USB**;
- cancellation/failure-state inspection;
- backup and restore-path sanity;
- acquisition behavior using a separately trusted signed local catalogue while the production channel is disabled;
- diagnostic export and keyboard navigation;
- 1280×800 visibility of confirmation, progress, action, and Close controls in report-heavy dialogs.

Do not convert software-only results into a universal hardware, whole-device-health, or Secure Boot claim.

## Install and rollback

Install or upgrade the release candidate:

```bash
sudo apt install ./rufusarm64_0.13.0_arm64.deb
```

Verify the package checksum first:

```bash
sha256sum -c rufusarm64_0.13.0_arm64.deb.sha256
```

Existing settings are retained. The package upgrades earlier RufusArm64 installations in place.

To roll back to the prior packaged release, keep its `.deb` and run:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.12.1_arm64.deb
```

To remove RufusArm64 while retaining normal user files:

```bash
sudo apt remove rufusarm64
```

A rollback does not restore or repair USB media already written by a newer release. Use **Restore / format…** only after selecting the exact removable drive and completing its fresh identity-bound plan and confirmation.
