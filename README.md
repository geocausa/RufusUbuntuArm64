# RufusArm64

RufusArm64 is an **independent, unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X devices such as Surface Pro 11 X1E. It is a native Linux implementation inspired by Rufus; it is not a Wine wrapper and is not endorsed by the official Rufus project.

## What it supports

- Direct, byte-for-byte writing of recognized Linux ISOHybrid images and GPT/MBR raw disk images.
- Safe preparation of ZIP, gzip, bzip2, XZ, LZMA, and Zstandard-compressed images.
- VHD, VHDX, QCOW2, and VMDK restoration through validated `qemu-img` conversion with backing-file and encryption rejection.
- Windows installation media using GPT or MBR and **Automatic, FAT32, or NTFS** filesystem selection.
- Native FAT32 UEFI boot with automatic splitting of oversized `install.wim` or `install.esd` files.
- Checksum-pinned Rufus 4.15 UEFI:NTFS media for Windows NTFS/UEFI boot on ARM64, x86-64, and x86 firmware.
- True Windows legacy BIOS/CSM media for x86 and x86-64 ISOs using an active MBR partition and BOOTMGR-compatible MBR/PBR boot code.
- Optional Windows Setup customizations through a generated `autounattend.xml`.
- Optional Windows driver staging and Windows PE auto-loading, with the normal **Load driver** button retained as a fallback.
- Optional Microsoft Secure Boot DBX download and pre-write EFI revocation scanning.
- Signed acquisition-catalog verification and checksum-gated, atomic image downloads through the CLI.
- Ubuntu casper and Debian live-boot persistence planning plus an explicit CLI-only experimental GPT/UEFI creation path with verified writable-tree copying and ext4 initialization.
- Full copied-file verification plus FAT32/NTFS consistency checks.
- Optional full zero-write formatting and a one-pass zero-pattern media check.

## Install on Ubuntu ARM64

```bash
sudo apt install ./rufusarm64_0.9.0_arm64.deb
```

The package upgrades older `rufusarm64` versions in place. Open **RufusArm64** from the application menu afterward.

## Basic use

1. Connect the USB drive.
2. Choose an ISO/raw image, a supported compressed image, or a VHD/VHDX/QCOW2/VMDK virtual disk.
3. Select the removable USB device.
4. For a Windows ISO, review **Partition scheme**, **Target system**, **File system**, and optional Windows Setup choices.
5. Leave copied-file verification enabled for qualification runs.
6. Click **Create USB**, carefully confirm the selected drive, and authenticate with Ubuntu.

Everything on the selected USB is permanently erased.

## Windows layouts

### ARM64 systems such as Surface Pro 11 X1E

Use an official Windows ARM64 ISO with:

```text
GPT / UEFI / Automatic or FAT32
```

Automatic prefers FAT32 and splits a large Windows image. NTFS is available through the pinned UEFI:NTFS loader, but native FAT32 remains the most firmware-compatible recovery choice.

Windows ARM64 does **not** support legacy PC BIOS/CSM boot. Selecting BIOS with an ARM64-only ISO is rejected before the USB partition table is erased.

### x86 and x86-64 PCs

Supported combinations include:

```text
GPT / UEFI / FAT32 or NTFS
MBR / UEFI / FAT32 or NTFS
MBR / BIOS or UEFI-CSM / FAT32 or NTFS
```

BIOS/CSM mode installs an active MBR partition, a pinned Windows 7-compatible MBR bootstrap, and the matching FAT32 or NTFS BOOTMGR partition boot record. The ISO must contain a root `bootmgr` file and x86/x86-64 boot files.

## Filesystem behavior

**Automatic** prefers FAT32 when every ISO path is FAT-compatible and all oversized Windows payloads can be represented safely. It selects NTFS when another file or filename cannot be represented on FAT32.

**FAT32** uses the firmware-native UEFI path. An oversized `install.wim` or `install.esd` is prepared as numbered `.swm` parts before the USB is erased.

**NTFS** keeps the installation image intact. UEFI mode creates a small, checksum-verified `RUFUS_BOOT` partition containing Rufus 4.15's architecture-aware UEFI:NTFS loader. BIOS mode uses the standard Windows NTFS BOOTMGR boot record instead.

## Optional Windows drivers

Choose a folder containing complete signed Windows driver packages, including their `.inf`, `.sys`, `.cat`, and related files. RufusArm64:

- rejects symbolic links and non-regular files;
- copies the folder to `USB\drivers`;
- writes a root marker used to locate the installation media in Windows PE;
- generates a windowsPE command that recursively calls `drvload` for the `.inf` files before disk selection;
- leaves the files available for manual **Load driver** selection if automatic loading does not match the hardware.

The drivers are not injected into Microsoft's signed `boot.wim` or `install.wim` images.

## Windows Setup options

Every change is opt-in. Available choices include:

- bypassing TPM 2.0, Secure Boot, and minimum-RAM checks;
- hiding the online-account screens where supported;
- creating a named local administrator account;
- reducing initial data collection and consumer-content settings;
- disabling automatic BitLocker device-encryption provisioning;
- applying a validated locale and mapped Windows time zone.

The source ISO is not modified. RufusArm64 writes or replaces `autounattend.xml` only on the created USB.

## Safety design

The privileged helper:

- accepts whole block devices beneath `/dev`, not partitions;
- refuses read-only devices and the disk backing the running Ubuntu system;
- hides internal MMC/eMMC and normal fixed disks from the default GUI list;
- binds the selected source and target to refreshed device identities;
- holds the selected source through an open descriptor and hashes its bytes before destructive work;
- rejects source mutation during raw and Windows-media writes;
- revalidates the target before each destructive phase;
- uses descriptor-relative, no-symlink traversal for untrusted driver folders;
- flushes block buffers before verification and uses aligned direct I/O when supported;
- verifies embedded UEFI:NTFS and legacy BIOS boot assets against pinned SHA-256 values;
- reads back generated partition tables and boot-code patches;
- requires fresh Polkit authorization for each graphical write;
- prevents the window from closing during an active write and supports protected cancellation.

## Bundled components

The ARM64 package includes a package-private `wimlib-imagex` 1.14.5 binary built for AArch64. Its upstream source archive, exact commit, build configuration, notices, and checksum are installed under `/usr/share/doc/rufusarm64/wimlib/`.

The package also includes Rufus 4.15's pinned `uefi-ntfs.img` and GPL ms-sys-derived Windows MBR/PBR byte arrays. The corresponding upstream source files, pin metadata, and checksums are installed under `/usr/share/doc/rufusarm64/`.

## Secure Boot DBX checks

The **Update** button downloads the architecture-specific `DBXUpdate.bin` from Microsoft’s public `secureboot_objects` repository into the current user’s cache. Selecting that file makes Windows-media creation scan EFI boot files before the USB is erased. RufusArm64 checks the Authenticode image hash and exact X.509 certificates embedded in the signature against DBX entries.

This is a media-safety check. It does not write the DBX into firmware, change Secure Boot settings, or claim to perform online certificate revocation. The downloaded file must use the authenticated UEFI variable-update structure, but version 0.9.0 trusts Microsoft’s HTTPS/GitHub distribution channel rather than independently validating the PKCS#7 update signature.

## Secure image acquisition foundation

Version 0.9.0 adds a strict CLI foundation for future ISO acquisition. A catalog is accepted only after detached Ed25519 verification, expiry checks, safe filename/HTTPS/redirect validation, exact-size enforcement, and final SHA-256 verification. Downloads are installed atomically and existing files are reused only after a complete hash match. See `docs/acquisition-catalog.md`. No public remote catalog or graphical picker is enabled yet.

## Linux persistence planning foundation

Version 0.9.0 can inspect a plain ISOHybrid image plus a read-only mounted or extracted media tree and produce a non-destructive persistence plan. The initial scope is Ubuntu 20.04+ casper media (`persistent`, ext4 label `casper-rw`) and Debian live-boot media (`persistence`, ext4 label `persistence`, root `persistence.conf` containing `/ union`). MBR and GPT metadata are validated before a plan is returned, including both GPT copies and their CRCs. See `docs/persistence-planning.md`.

The codebase also contains separately tested primitives for applying exact partition plans, atomically patching writable boot trees without following symbolic links, creating/checking ext4 persistence filesystems, and building plus copying SHA-256 manifests from read-only Linux media trees. The copy layer checks FAT32 names, case collisions, file-size limits and architecture-specific fallback UEFI loaders, and only dereferences file links that resolve beneath the source root. See `docs/linux-media-copy.md`.

A CLI-only experimental writer now connects these foundations for supported GPT/UEFI media. It creates a fresh FAT32 EFI System Partition and ext4 persistence partition under one target lock, verifies both GPT copies, copies and rehashes the media tree, patches only approved boot configurations, re-detects the activated contract, and checks both filesystems. The graphical path rejects this mode. See `docs/persistence-create.md`. Each created USB also receives a canonical creation record and checksum for the two-stage `qualify start` / reboot / `qualify verify` workflow described in `docs/persistence-qualification.md`. This evidence confirms one successful persistent reboot; it does not replace a published physical-hardware matrix.

## Current limitations

RufusArm64 is not yet feature-equivalent to every official Rufus mode. Version 0.9.0 still does not include Windows To Go, stable GUI-supported Linux persistence, FreeDOS creation, a built-in remote ISO catalog, or FFU restoration. FFU remains explicit rather than deceptive: official Rufus uses Windows’ FFU provider, and a safe Linux-native restore provider has not been integrated.

Full Authenticode signer-chain construction, every Linux ISO-specific Syslinux/GRUB workaround, and broad physical-hardware qualification remain ongoing. Passing automated tests cannot prove that every firmware or storage controller will boot.

## Build and test

Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, and the verified ARM64 WIM engine in `vendor/wimlib/arm64/`.

```bash
./scripts/test.sh
```

The installer is produced at:

```text
dist/rufusarm64_0.9.0_arm64.deb
```

## Command line

```bash
rufusarm64-cli list
rufusarm64-cli inspect --image Windows.iso.xz --json
rufusarm64-cli dbx update --arch arm64 --json
rufusarm64-cli dbx inspect --file ~/.cache/rufusarm64/dbx/arm64-DBXUpdate.bin
rufusarm64-cli acquire verify --catalog catalog.json --signature catalog.json.sig --public-key catalog.pub
rufusarm64-cli acquire list --catalog catalog.json --signature catalog.json.sig --public-key catalog.pub
rufusarm64-cli persistence plan --image ubuntu.iso --media-root /mnt/ubuntu --target-size 64G --size 16G --json
sudo rufusarm64-cli write --mode linux-persistent --experimental-persistence --image ubuntu.iso --device /dev/sdX --persistence-size 16G
sudo rufusarm64-cli qualify start --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-initial.json
# Reboot the same persistent USB, then:
sudo rufusarm64-cli qualify verify --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-verified.json
sudo rufusarm64-cli write \
  --image Windows.iso --device /dev/sdX \
  --partition-scheme mbr --target-system bios \
  --filesystem ntfs \
  --dbx-file ~/.cache/rufusarm64/dbx/arm64-DBXUpdate.bin --verify
```

The GUI supplies device-identity binding and protected cancellation automatically and is recommended for normal use.

## License

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
