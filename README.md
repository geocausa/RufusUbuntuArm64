# RufusArm64

RufusArm64 is an **independent, unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X systems such as Surface Pro 11 X1E. It is a native Linux implementation inspired by Rufus; it is not a Wine wrapper and is not endorsed by the official Rufus project.

**Version 0.13.0** is the Stage 2 practical-parity release candidate.

## Highlights

- Direct writing of recognized Linux ISOHybrid images and GPT/MBR raw disk images.
- Bounded Linux compatibility reporting for hybrid layouts, optical-only ISO media, El Torito BIOS/UEFI entries, and ISOLINUX/SYSLINUX/GRUB fingerprints.
- Safe preparation of ZIP, gzip, bzip2, XZ, LZMA, Zstandard, VHD, VHDX, QCOW2, and VMDK inputs.
- Windows installation media using GPT or MBR, UEFI or x86-family BIOS/CSM, and Automatic, FAT32, or NTFS selection.
- Bounded Windows multi-edition reporting for WIM, ESD, and validated split SWM payloads before optional Setup customizations.
- A guarded graphical persistent Ubuntu casper and Debian live-boot workflow.
- A guarded **Restore / format…** workflow for verified data-only GPT/MBR media using FAT32, exFAT, NTFS, or ext4.
- Fast deterministic **FreeDOS…** media creation from checksum-pinned, source-retained FreeDOS 1.4 and FreeCOM payloads for x86 BIOS or UEFI Legacy/CSM systems, with required-extent write/readback rather than capacity-scaled whole-device cloning.
- Explicit post-operation actions to create another USB or restore the exact completed target for ordinary storage.
- Threshold-signed and local-signed image-catalog verification, storage preflight, cancellation, SHA-256 installation, and resumable private partials.
- Descriptor-safe UEFI, DBX, and SBAT analysis plus optional ARM64 boot-time media-integrity validation for supported persistent media.
- A guarded **Save drive image…** workflow that captures a removable drive read-only into a new SHA-256-reported image without replacing existing files.
- Keyboard mnemonics, safe visible shortcuts, assistive-technology metadata, selectable status text, and exportable diagnostics.
- Whole-device, source-identity, target-identity, mount, system-disk, cancellation, filesystem, and post-copy verification safeguards.

## Install on Ubuntu ARM64

Verify the release-candidate checksum and install:

```bash
sha256sum -c rufusarm64_0.13.0_arm64.deb.sha256
sudo apt install ./rufusarm64_0.13.0_arm64.deb
```

The package upgrades older `rufusarm64` installations in place. One visible **RufusArm64** application entry is installed. Normal launch opens the composed writer; `rufusarm64 --persistence` remains available for the guarded persistent-media workflow.

## Create ordinary boot media

1. Connect a removable USB drive.
2. Open **RufusArm64**.
3. Choose a recognized image or select **Download…** for verified acquisition.
4. Review the image compatibility and write-path explanation.
5. Select the exact removable USB device.
6. For Windows media, review the partition scheme, target system, filesystem, payload/edition facts, and optional Setup choices.
7. Keep verification enabled for qualification runs.
8. Select **Create USB**, verify the destructive warning, and authenticate.

Everything on the selected target is permanently erased. The final destructive dialog defaults to Cancel. No keyboard shortcut is bound directly to erasure.

After completion, RufusArm64 can retain the image for **Create another USB** or open the existing guarded **Restore drive for storage…** path for the exact target. Neither action erases automatically.

## Verified image acquisition

The composed graphical **Download…** workflow uses the existing native acquisition core:

- threshold-signed root and catalogue metadata for a package-owned channel;
- expiry, freeze, root-rotation, and rollback checks;
- separately trusted local catalogue/signature/public-key recovery;
- HTTPS and redirect-host restrictions;
- signed filename, exact size, and SHA-256 verification;
- destination storage-space preflight and atomic no-replace publication;
- owner-private, SHA-bound resumable partials;
- cancellation that never installs an unverified image.

The upstream production channel remains disabled until reviewed public mirrors, offline root-key operations, and a signed catalogue are provisioned. No private signing key is included in source, CI, packages, or artifacts.

## Linux compatibility reporting

For recognized plain raw/ISO inputs, RufusArm64 performs bounded local reads without mounting or executing image content. It reports:

- hybrid disk layout, optical-only ISO, or ordinary raw disk layout;
- validated El Torito BIOS and UEFI catalogue entries;
- ISOLINUX, SYSLINUX, or GRUB fingerprints found in referenced boot images;
- byte-for-byte preservation of embedded layout;
- a warning when optical-only USB boot may depend on firmware USB-CD emulation.

This structural report does not prove that a physical computer will boot the media.

## Windows ARM64 media

For systems such as Surface Pro 11 X1E, use an official Windows ARM64 ISO with:

```text
GPT / UEFI / Automatic or FAT32
```

Windows ARM64 does not support legacy PC BIOS/CSM boot. x86 and x86-64 Windows media may use MBR/BIOS only when compatible boot files and `bootmgr` are present.

Before optional customizations, the exact source ISO is mounted read-only. Every installation edition must agree on Windows generation, client/server family, and architecture. The options dialog reports edition count/names plus WIM, ESD, or complete split-SWM payload type and part count. Conflicting or unknown metadata disables customizations but does not block ordinary no-customization media creation.

Automatic mode prefers FAT32 and splits oversized WIM/ESD payloads when required. NTFS uses the pinned UEFI:NTFS image. Native FAT32 remains the most firmware-compatible ARM64 recovery path.

## Persistent Linux media

The guarded persistence path supports a deliberately narrow contract:

- plain raw-bootable ISOHybrid media;
- Ubuntu 20.04+ casper or Debian live-boot;
- GPT/UEFI;
- an architecture-matching fallback loader in `EFI/BOOT`;
- a FAT32-compatible live-media tree;
- a writable FAT32 boot partition and separate ext4 persistence partition;
- at least 1 GiB of persistence capacity.

Run the mandatory read-only analysis, review the fresh GPT/FAT32/ext4 plan, confirm the exact target, and keep the drive connected while data are copied, flushed, hashed, and checked.

For compatible ARM64 persistent media, **Validate media at UEFI boot** can transactionally preserve the original fallback loader, install the package-owned wrapper, and create `md5sum.txt`. **The canonical loader is built twice** from pinned upstream sources and accepted only when both binaries and provenance match byte-for-byte. It is unsigned. Secure Boot compatibility is not established.

Creation is not reboot qualification. On the created USB, record the first boot and later reboot:

```bash
sudo rufusarm64-cli qualify start \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-initial.json"

sudo rufusarm64-cli qualify verify \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-verified.json"
```

A passing report applies only to that exact image, USB, controller, firmware, Secure Boot state, and computer.

## Restore or format a USB for ordinary storage

Select a removable target and choose **Restore / format…**. RufusArm64 calculates an unprivileged identity-bound plan for GPT or MBR and FAT32, exFAT, NTFS, or ext4. It displays geometry, required tools, warnings, and an exact `FORMAT` phrase before administrator authentication.

A successful report verifies the partition geometry and filesystem. It does not claim bootability. Cancellation before erasure leaves the drive unchanged; cancellation or failure after erasure reports changed incomplete media conservatively.

## Create FreeDOS media

The **FreeDOS…** workflow creates deterministic FreeDOS 1.4 media from package-owned checksum-pinned payloads. It requires 512-byte logical sectors, an exact device identity/capacity, reviewed MBR/FAT32 geometry, and the phrase:

```text
WRITE FREEDOS 1.4 TO /dev/DEVICE FOR X86 BIOS LEGACY
```

The plan displays the exact required write and readback totals before authentication. Creation retains a nearly full-size FAT32 partition but writes and verifies only the final MBR, bounded head/tail clearing, FAT32 boot/FSInfo and reserved regions, both complete FAT tables, root directory, payload clusters, and allocation slack. Unallocated data clusters are intentionally untouched, so runtime scales with required filesystem structures rather than USB capacity.

A successful report confirms required-extent readback, the reviewed structure, and an extent-set SHA-256. It is not a whole-device health test; use **Check USB** for exhaustive write/readback qualification.

The resulting media targets **x86-compatible processors using BIOS or UEFI Legacy/CSM**. It is not for ARM64, UEFI-only, or Secure Boot-only systems. Software verification does not prove physical boot compatibility.

## Save a drive image

Select a removable drive and choose **Save drive image…**. RufusArm64 plans the destination without elevation, requires the exact `SAVE /dev/DEVICE TO /absolute/path/image.img` phrase, opens the source read-only through the package-owned helper, and atomically publishes only a complete synchronized SHA-256-accounted image. Existing files are never replaced and cancellation removes temporary output.

## Keyboard and accessibility

The image and target labels are mnemonics. Additional shortcuts are:

- `Ctrl+R` — refresh removable USB drives;
- `Ctrl+D` — open verified acquisition;
- `Ctrl+K` — calculate image checksums;
- `Ctrl+U` — open read-only UEFI media validation;
- `F1` — open About and licence information.

Create USB and active-operation cancellation have no direct accelerator. Key controls, status, diagnostics, compatibility reporting, and post-operation actions have assistive names and descriptions. Compatibility and progress-detail text can be selected and copied.

## Safety model

Privileged helpers:

- accept only whole block devices beneath `/dev`;
- refuse partitions, read-only targets, and the disk backing the running system;
- hide normal fixed disks from the default graphical list;
- bind selected source and target to refreshed identities;
- revalidate immediately before destructive phases;
- retain locks and descriptors through write, flush, required readback, and final checks;
- reject unsafe symbolic-link traversal and source mutation;
- verify packaged boot assets, copied files, structures, and filesystems;
- require fresh Polkit authorization and support protected cancellation.

Software checks never establish universal physical boot, persistence, whole-device health, or Secure Boot compatibility. Complete the human checklist in `docs/hardware-checklist-0.13.0.md` before public release.

## Build and test

Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, the verified ARM64 WIM engine, and source-retained package-private boot assets.

```bash
./scripts/test.sh
```

The release-candidate package is produced at:

```text
dist/rufusarm64_0.13.0_arm64.deb
```

## Command-line examples

```bash
rufusarm64-cli list --json
rufusarm64-cli inspect --image ubuntu.iso --json
rufusarm64-cli hash --all ubuntu.iso
rufusarm64-cli acquire channel list --json
rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --firmware-sbat --json
rufusarm64-cli persistence plan --image ubuntu.iso --media-root /mnt/ubuntu --target-size 64G --size 16G --json
rufusarm64-freedos-format --device /dev/sdX --expected-identity TOKEN --label FREEDOS --dry-run --json
rufusarm64-nonbootable-format --device /dev/sdX --expected-identity TOKEN --filesystem exfat --dry-run --json
```

## Release evidence and rollback

See:

- `docs/release-0.13.0.md` for release notes, boundaries, installation, and rollback;
- `docs/hardware-checklist-0.13.0.md` for the mandatory real-machine GO/NO-GO record;
- `docs/persistence-qualification.md` for exact persistence evidence;
- `docs/freedos-user-guide.md` for the FreeDOS boundary.

Rollback to the previous package with:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.12.1_arm64.deb
```

Rollback does not repair USB media already written. Use the guarded restoration workflow only after selecting and confirming the exact removable target.

## License

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
