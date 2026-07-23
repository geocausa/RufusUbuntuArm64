# RufusArm64 0.13.0

## Highlights

RufusArm64 0.13.0 is the Stage 2 practical-parity release for Ubuntu ARM64.

- **Restore / format…** creates verified ordinary data storage through a separate identity-bound formatter supporting GPT or MBR and FAT32, exFAT, NTFS, or ext4.
- **FreeDOS…** creates a deterministic, checksum-pinned FreeDOS 1.4 layout through bounded quick-format-style writes and required-extent readback. It retains a nearly full-size FAT32 partition and targets x86 BIOS or UEFI Legacy/CSM computers only.
- Main-writer completion offers explicit **Create another USB** and **Restore drive for storage…** actions without erasing anything automatically.
- Linux raw/ISO inspection distinguishes hybrid media from optical-only ISOs, validates El Torito BIOS/UEFI entries, and reports ISOLINUX, SYSLINUX, and GRUB fingerprints when present in referenced boot images.
- Verified image acquisition is exposed in the composed GTK application with cancellation, storage preflight, signed size/SHA-256 installation, and SHA-bound resumable private partials.
- Keyboard mnemonics, safe visible shortcuts, assistive-technology metadata, and selectable compatibility/status text improve non-mouse use.
- Report-heavy GTK dialogs keep confirmation, progress, action, and Close controls visible while long details and reports remain scrollable.
- Windows setup analysis reports bounded edition names/count plus WIM, ESD, or validated split-SWM payload type and part count before optional customizations are enabled.
- Windows layout defaults are image-derived: supported ARM64/UEFI media selects GPT/UEFI, while proven x86/x64 BIOS-only installation media can select MBR/BIOS.
- Ordinary source images are held stable with a Linux kernel read lease where supported, reducing redundant full-source reads without weakening identity, digest, cancellation, or destination verification.

The existing raw, compressed, virtual-disk, Windows, persistence, UEFI, backup, qualification, cancellation, identity, and verification paths remain in place.

## Real-hardware release evidence

The 0.13.0 hardware record includes:

- Ubuntu ARM64 media creation and boot on the intended ARM64 host;
- persistent Ubuntu creation, boot, saved change, shutdown, reboot, and retained change;
- Windows ARM64 installation-media creation;
- non-bootable FAT32 creation and verification on removable media;
- high-DPI GTK use at 2880×1920 with 200% scaling;
- FreeDOS creation on a 29.2 GiB Lexar JumpDrive with 17,989,632 bytes written and the same number read back under `required-filesystem-extents` verification;
- FreeDOS extent-set SHA-256 `41d6180cc0a53c79cabf28c39314b8daa0f26f926503c32f75a498436c4dc262`.

No x86 BIOS/Legacy or UEFI-CSM machine was available for a physical FreeDOS boot attempt. That observation is explicitly untested and deferred to community feedback; it is not recorded as a pass. See `docs/hardware-checklist-0.13.0.md` for the signed-off scope.

## Safety and support boundaries

Every write, restore/format, FreeDOS creation, qualification, or persistent-media operation can destroy all accessible data on the selected target. Confirm the device path, model, capacity, and generated phrase before authentication.

Software verification is not physical boot qualification. The deterministic FreeDOS workflow proves the reviewed final MBR/FAT32 boot and filesystem extents were written and read back; it deliberately does not overwrite or qualify unallocated data clusters. Use **Check USB** for exhaustive whole-device testing. Neither result proves that a particular x86 BIOS/Legacy computer will boot the media.

FreeDOS media is not for ARM64 or UEFI-only computers. Windows ARM64 media remains UEFI-only. Windows To Go, FFU restoration, encrypted persistence, and arbitrary bootloader replacement remain unsupported.

The package-owned ARM64 `uefi-md5sum` loader remains unsigned. **Secure Boot compatibility is not established** for that optional persistent-media wrapper. DBX and SBAT inspection is read-only and does not modify firmware.

The production built-in acquisition channel remains disabled until reviewed public mirrors, offline root-key operations, and a signed catalogue are provisioned. The separately trusted local signed-catalogue recovery workflow remains available. No private signing key is included in the repository, CI, package, or release artifacts.

## Verification and release construction

The exact release tag must pass the complete repository suite, native ARM64 execution, reproducible Debian packaging, loop-device formatter qualification, FreeDOS loop qualification, WIM/UEFI reproduction, static analysis, vulnerability scanning, Lintian, AppStream, desktop-file, and package-content gates.

The immutable tag workflow publishes:

- `rufusarm64_0.13.0_arm64.deb`;
- `rufusarm64_0.13.0_arm64.deb.sha256`;
- the corresponding RufusArm64 source archive;
- the pinned wimlib source archive;
- the pinned uefi-md5sum source archive and checksum.

Do not convert software-only results into a universal hardware, whole-device-health, Secure Boot, or legacy-boot claim.

## Install and rollback

Verify the package checksum:

```bash
sha256sum -c rufusarm64_0.13.0_arm64.deb.sha256
```

Install or upgrade:

```bash
sudo apt install ./rufusarm64_0.13.0_arm64.deb
```

Existing settings are retained. The package upgrades earlier RufusArm64 installations in place.

To roll back to the prior packaged release, keep its package and run:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.12.1_arm64.deb
```

To remove RufusArm64 while retaining normal user files:

```bash
sudo apt remove rufusarm64
```

A rollback does not restore or repair USB media already written by a newer release. Use **Restore / format…** only after selecting the exact removable drive and completing its fresh identity-bound plan and confirmation.
