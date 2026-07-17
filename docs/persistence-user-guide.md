# Persistent live USB user guide

RufusArm64 can create a persistent live USB for a deliberately narrow set of Ubuntu and Debian images.

## Use the persistent-media application

The **Create USB** button in the main RufusArm64 window performs an ordinary image write. For a Linux ISOHybrid image, it preserves the image byte-for-byte and therefore creates a normal non-persistent live USB.

To create persistent media, open **RufusArm64 Persistent Live USB** from the application menu, or run:

```text
rufusarm64 --persistence
```

The dedicated entry point is also available as:

```text
rufusarm64-persistence
```

Only the dedicated persistent-media application presents **Erase and create persistent USB** and invokes the restricted persistence helper.

## What persistence means

The result is still a **live operating system**. RufusArm64 copies the ISO's live-media tree to a writable FAT32 boot partition, enables the distribution's persistence boot parameter, and creates a separate ext4 partition for changed files.

For supported Ubuntu media the boot parameter is `persistent` and the ext4 partition is labelled `casper-rw`. For supported Debian live-boot media the boot parameter is `persistence`, the ext4 partition is labelled `persistence`, and its root contains `persistence.conf` with `/ union`.

Ordinary files, many settings, and packages installed inside the live session can therefore remain after a reboot. This is not equivalent to installing Ubuntu normally onto the USB. Major distribution upgrades, bootloader replacement, kernel/initramfs changes, encrypted persistence, and arbitrary derivative distributions are outside the supported contract.

## Current supported scope

The graphical wizard accepts only media that pass all preflight checks:

- a plain, recognized, raw-bootable Linux ISOHybrid image;
- Ubuntu 20.04 or newer using casper, including modern daily images that identify the casper kernel through `/casper/vmlinuz` and provide `casper/install-sources.yaml`, or Debian using live-boot;
- a detector-approved kernel command and boot configuration that can be patched without following symbolic links;
- a matching fallback UEFI loader in `EFI/BOOT`;
- a FAT32-safe media tree;
- bounded relative file and directory symbolic links whose resolved targets stay inside the mounted ISO;
- GPT/UEFI creation with one FAT32 boot partition and one ext4 persistence partition;
- at least 1 GiB of persistence storage.

Traditional Ubuntu configurations may contain `boot=casper`. Newer configurations may instead use a command such as `linux /casper/vmlinuz $cmdline ---`. RufusArm64 recognizes both forms and inserts `persistent` before the `---` separator while leaving unrelated kernel entries unchanged.

FAT32 cannot store Unix symbolic links. Safe in-tree links are therefore materialized as ordinary files or directories. A repository alias such as `dists/stable -> resolute` becomes a real `dists/stable` directory containing verified copies of the target files. Those duplicate files count toward entry, byte, FAT32-capacity, copy, and verification limits. Absolute links, links that escape the ISO, directory cycles, device nodes, case-colliding paths, and unbounded expansions are refused.

Compressed images, virtual disks, MBR persistence, BIOS-only media, files too large for FAT32, encrypted persistence, and unrecognized boot layouts are refused. An unversioned derivative must include modern casper metadata; a kernel path alone is not enough to weaken the compatibility gate.

## Creation workflow

1. Open **RufusArm64 Persistent Live USB**.
2. Select the plain Linux ISO and the exact removable USB drive.
3. Choose the persistence size. Zero uses all suitable capacity remaining after the live-media partition.
4. Run **Analyze selected image**. This step is mandatory and read-only: it mounts only the identity-bound ISO in a private workspace and supplies only the USB's reported capacity. It does not open the USB device.
5. Review the detected distribution, ext4 label, boot parameter, fresh GPT layout, required FAT32 capacity, and boot files that will be updated.
6. Select **Erase and create persistent USB** and verify the exact device in the final warning. All existing data on that USB is destroyed.
7. Keep the USB connected until RufusArm64 reports completion or confirms cancellation cleanup. Copying, filesystem checks, and final buffer flushing can take several minutes on slower flash drives.

The privileged creation helper repeats the pre-authentication source and target identity checks, revalidates the removable-drive policy immediately before destructive work, copies and hashes the live-media tree, patches only detector-approved boot files, checks FAT32 and ext4, and flushes the target before success.

## Qualification after creation

Automated verification cannot prove that a particular firmware will boot the result. Boot the new USB on the intended computer and locate the creation record on the writable boot partition, commonly at `/cdrom/.rufusarm64/creation.json` on Ubuntu.

Run the initial probe inside the persistent live session:

```text
sudo rufusarm64-cli qualify start \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-initial.json"
```

Create a small test file in the home directory or make another harmless persistent change, then reboot the same computer from the same USB. After reboot, confirm the change survived and run:

```text
sudo rufusarm64-cli qualify verify \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-verified.json"
```

A passing verification confirms that the expected persistence parameter and overlay root were active and that private state survived one reboot on that exact image, USB, controller, firmware, and computer. Preserve both reports, their SHA-256 sidecars, the ISO checksum, and hardware/firmware details as qualification evidence.

## Practical cautions

Keep important files backed up elsewhere. Flash media can fail, and a persistent live overlay is not a replacement for a normally installed and maintained operating system. Avoid treating an unqualified USB as your only recovery environment. Secure Boot and firmware behavior remain properties of the selected image and the tested machine, not guarantees made solely by successful media creation.
