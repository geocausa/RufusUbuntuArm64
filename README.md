# RufusArm64

RufusArm64 is an **unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X Elite devices such as Surface Pro 11 X1E.

The graphical application supports:

- Writing recognized Linux ISOHybrid images and GPT/MBR raw disk images directly to USB.
- Creating modern Windows ARM64 UEFI installation USBs from standard Windows ISOs.
- GPT, UEFI and FAT32 Windows-media preparation with automatic `install.wim`/`install.esd` splitting.
- Optional Windows Setup customizations through a generated `autounattend.xml`, including regional settings detected from Ubuntu.
- Post-write verification after Linux block buffers have been flushed.

It is independent from, and is not endorsed by, the official Rufus project.

## Install on Ubuntu ARM64

Download the ARM64 `.deb`, then open it in Ubuntu App Center or install it from Terminal:

```bash
sudo apt install ./RufusArm64_0.4.0_Ubuntu_ARM64.deb
```

Open **RufusArm64** from the application menu afterward.

## Use it

1. Connect the USB drive.
2. Open **RufusArm64**.
3. Choose an `.iso`, `.img`, `.raw`, or `.bin` image.
4. Select the USB drive.
5. Review the detected layout under **Advanced drive properties**.
6. For a Windows ISO, choose any optional Windows Setup changes or leave every box unchecked.
7. Leave verification enabled, click **Create USB**, carefully confirm the drive, and enter your Ubuntu administrator password.
8. Keep the application open until it reports success or confirms cancellation.

Everything on the selected USB drive is erased.

On ARM64 builds, RufusArm64 refuses an x86-64-only Windows ISO before erasing the USB. For Surface Pro 11 X1E, use an official **Windows ARM64 ISO**.

## Windows Setup options

When a standard Windows installation ISO is detected, RufusArm64 can optionally:

- bypass TPM 2.0, Secure Boot and minimum-RAM checks;
- remove the Microsoft online-account requirement where supported by that Windows release;
- create a named local administrator account;
- skip initial privacy prompts and reduce advertising/consumer-content policies;
- use the current Ubuntu locale and a safely mapped Windows time zone;
- disable automatic BitLocker device-encryption provisioning.

The ISO is not modified. Selected options are written to `autounattend.xml` on the USB. Available choices include hardware-check bypasses, offline/local-account setup, reduced setup data collection, automatic BitLocker provisioning control, and the current Ubuntu user's regional settings. Leaving every option unchecked creates standard Microsoft installation media.

## Supported media

### Linux and raw images

- ISOHybrid Linux images
- Recognized GPT and MBR disk images
- Byte-for-byte verification after a kernel block-cache flush

The partition table and filesystems are embedded in these images, so RufusArm64 correctly displays the layout as **From image** instead of offering unsafe formatting choices.

### Windows installation media

- Standard modern Windows UEFI installation ISOs
- ARM64 UEFI removable-media boot files
- Directly generated GPT partition table and FAT32 EFI System Partition (without waiting on the host-wide udev queue)
- Editable FAT32 volume label
- Automatic WIM/ESD splitting on the computer before the USB is erased
- Exact size checks for every generated split part
- SHA-256 comparison of copied setup files
- Read-only remount verification and FAT32 filesystem checking

For Windows ARM64 on Surface Pro 11 X1E, GPT/UEFI/FAT32 is intentional. MBR and legacy BIOS are not offered because they are not valid targets for that device.

## WIM engine

RufusArm64 includes its own package-private ARM64 `wimlib-imagex` 1.14.5
engine. Windows ISOs with large `install.wim` or `install.esd` files therefore
work immediately after installing RufusArm64; Ubuntu's separate `wimtools`
package is not required.

The bundled command-line engine was built natively on Ubuntu 24.04 ARM64 with
FUSE and direct NTFS support disabled. It links only to the standard GNU C
runtime. Its licence, exact upstream commit, build configuration, checksum and
corresponding source archive are included with the release.

## Safety design

The privileged helper:

- accepts only whole block devices beneath `/dev`;
- refuses partitions, read-only devices, and the disk backing the running Ubuntu system;
- hides internal MMC/eMMC and fixed disks from the normal graphical list;
- identity-binds the selected image and the selected USB drive;
- refreshes identity and mount state immediately before destructive commands;
- prevents desktop automount interference while copying or verifying;
- removes stale primary and backup disk signatures before raw writing;
- flushes and invalidates block buffers before verification;
- prevents the GUI from closing while a write is active;
- supports protected cancellation across `pkexec`;
- checks temporary free space, USB capacity, FAT32 filename compatibility and generated split-part sizes before erasing Windows media;
- requires a fresh Polkit authentication for each graphical write.

## Version 0.4 limitations

- Modern UEFI media only; no legacy BIOS/CSM or Windows To Go.
- No Linux persistence partition or bad-block scan yet.
- No compressed `.xz`/`.zst` image streaming yet.
- Windows unattended options depend on behavior that Microsoft can change between releases; Windows may ignore an option on a future build.
- A container cannot physically boot-test every generated USB. Real hardware qualification remains necessary.

## Build and test from source

Requirements are Go 1.22 or newer, Python 3, Debian packaging tools, and a verified ARM64 WIM engine. On an ARM64 build machine, create the pinned package-private engine first:

```bash
sudo apt install build-essential autoconf automake libtool pkg-config git \
  libxml2-dev zlib1g-dev liblzma-dev libbz2-dev liblz4-dev libzstd-dev
./scripts/build-wimlib-arm64.sh
VERSION=0.4.0 ./scripts/test.sh
```

Release CI performs the WIM-engine build on a native Ubuntu ARM64 runner and passes the resulting verified binary into the package job.

The ARM64 installer is produced at:

```text
dist/rufusarm64_0.4.0_arm64.deb
```

## Command-line interface

The graphical package also installs `rufusarm64-cli`:

```bash
rufusarm64-cli list
rufusarm64-cli inspect --image Windows.iso --json
sudo rufusarm64-cli write --image ubuntu.iso --device /dev/sdX --verify
```

The GUI supplies device-identity binding, Windows option selection and protected cancellation automatically, so it is recommended for normal use.

## License and relationship to Rufus

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
