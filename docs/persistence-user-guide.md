# Persistent live USB user guide

RufusArm64 can create a persistent live USB for a deliberately narrow set of Ubuntu and Debian images.

## What persistence means

The result is still a **live operating system**. RufusArm64 copies the ISO's live-media tree to a writable FAT32 boot partition, enables the distribution's persistence boot parameter, and creates a separate ext4 partition for changed files.

For supported Ubuntu media the boot parameter is `persistent` and the ext4 partition is labelled `casper-rw`. For supported Debian live-boot media the boot parameter is `persistence`, the ext4 partition is labelled `persistence`, and its root contains `persistence.conf` with `/ union`.

Ordinary files, many settings, and packages installed inside the live session can therefore remain after a reboot. This is not equivalent to installing Ubuntu normally onto the USB. Major distribution upgrades, bootloader replacement, kernel/initramfs changes, encrypted persistence, and arbitrary derivative distributions are outside the supported contract.

## Current supported scope

The graphical wizard accepts only media that pass all preflight checks:

- a plain, recognized, raw-bootable Linux ISOHybrid image;
- Ubuntu 20.04 or newer using casper, or Debian using live-boot;
- a matching fallback UEFI loader in `EFI/BOOT`;
- a FAT32-safe media tree;
- GPT/UEFI creation with one FAT32 boot partition and one ext4 persistence partition;
- at least 1 GiB of persistence storage.

Compressed images, virtual disks, MBR persistence, BIOS-only media, files too large for FAT32, encrypted persistence, and unrecognized boot layouts are refused.

## Start the wizard

Use the **RufusArm64 Persistent Live USB** application entry, or run:

```text
rufusarm64 --persistence
```

The dedicated entry point is also available as:

```text
rufusarm64-persistence
```

## Creation workflow

1. Select the plain Linux ISO and the exact removable USB drive.
2. Choose the persistence size. Zero uses all suitable capacity remaining after the live-media partition.
3. Run **Analyze selected image**. This step is mandatory and read-only: it mounts only the identity-bound ISO in a private workspace and supplies only the USB's reported capacity. It does not open the USB device.
4. Review the detected distribution, ext4 label, boot parameter, and boot files that will be updated.
5. Select **Erase and create persistent USB** and verify the exact device in the final warning. All existing data on that USB is destroyed.
6. Keep the USB connected until RufusArm64 reports completion or confirms cancellation cleanup.

The privileged creation helper repeats the pre-authentication source and target identity checks, revalidates the removable-drive policy immediately before destructive work, copies and hashes the live-media tree, patches only detector-approved boot files, checks FAT32 and ext4, and flushes the target before success.

## Qualification after creation

Automated verification cannot prove that a particular firmware will boot the result. Boot the new USB on the intended computer and locate the creation record on the writable boot partition, commonly at `/cdrom/.rufusarm64/creation.json` on Ubuntu.

Run the initial probe inside the persistent live session:

```text
sudo rufusarm64-cli qualify start \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-initial.json"
```

Reboot the same computer from the same USB, then run:

```text
sudo rufusarm64-cli qualify verify \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-verified.json"
```

A passing verification confirms that the expected persistence parameter and overlay root were active and that private state survived one reboot on that exact image, USB, controller, firmware, and computer. Preserve both reports, their SHA-256 sidecars, the ISO checksum, and hardware/firmware details as qualification evidence.

## Practical cautions

Keep important files backed up elsewhere. Flash media can fail, and a persistent live overlay is not a replacement for a normally installed and maintained operating system. Avoid treating an unqualified USB as your only recovery environment. Secure Boot and firmware behavior remain properties of the selected image and the tested machine, not guarantees made solely by successful media creation.
