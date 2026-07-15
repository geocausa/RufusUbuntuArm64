# RufusArm64

RufusArm64 is an **unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X Elite devices such as Surface Pro 11 X1E.

It provides a graphical application and supports two common jobs:

- Writing Linux ISOHybrid images and raw `.img` files directly to USB.
- Creating modern Windows UEFI installation USBs from standard Windows ISOs, using FAT32 and automatically splitting an oversized `install.wim` or `install.esd` file.

It is not produced or endorsed by the official Rufus project.

## Install on Ubuntu ARM64

Download the ARM64 `.deb` release, then either open it with Ubuntu's App Center or install it from a terminal:

```bash
sudo apt install ./rufusarm64_0.2.0_arm64.deb
```

Ubuntu will install the required system tools automatically. Open **RufusArm64** from the application menu afterward.

## Use it

1. Connect a USB drive.
2. Open **RufusArm64**.
3. Choose the ISO or disk-image file.
4. Choose the USB drive.
5. Leave verification enabled.
6. Click **Create USB**, confirm the selected drive, and enter your Ubuntu administrator password.
7. Wait for the success message before removing the drive.

Everything on the selected USB drive is erased.

For Windows on Surface Pro 11 X1E, choose an official **Windows ARM64** ISO. An x86-64 Windows ISO can be copied, but it will not boot an ARM64 Surface.

## Supported media

### Linux and raw images

- ISOHybrid Linux images
- Raw `.img`, `.raw`, and similar disk images
- Full byte-for-byte verification after writing

### Windows installation media

- Standard Windows 10/11 UEFI installation ISOs
- ARM64 and x86-64 UEFI boot files
- GPT partition table
- FAT32 EFI System Partition
- Automatic `install.wim`/`install.esd` splitting through Ubuntu's `wimtools`
- Optional SHA-256 verification of copied setup files

## Safety design

The privileged helper:

- accepts only whole block devices under `/dev`;
- refuses partitions and read-only devices;
- refuses the disk backing the running Ubuntu system;
- hides fixed internal disks from the normal graphical device list;
- refuses an image stored on the selected target disk;
- unmounts the target before writing;
- uses an exclusive writer lock and explicit flush;
- requires a final destructive-action confirmation in the GUI.

## Current limitations

Version 0.2.0 targets modern UEFI installation media. It does not yet provide legacy BIOS mode, Windows To Go, Rufus Windows-installation bypass customizations, multiboot menus, persistent Linux partitions, bad-block scanning, or compressed `.xz`/`.zst` image streaming.

The build and automated tests pass in the development environment. A physical USB boot test on every supported ARM64 computer is not possible in CI, so hardware feedback remains important.

## Build from source

Requirements for building are Go 1.22 or newer, Python 3, and `dpkg-deb`.

```bash
./scripts/test.sh
```

The ARM64 installer is produced at:

```text
dist/rufusarm64_0.2.0_arm64.deb
```

## Command-line interface

The graphical package also installs `rufusarm64-cli`:

```bash
rufusarm64-cli list
sudo rufusarm64-cli write --image ubuntu.iso --device /dev/sdX --verify
```

Use the graphical app unless command-line operation is specifically needed.

## License and relationship to Rufus

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. This implementation does not claim official Rufus status or endorsement.
