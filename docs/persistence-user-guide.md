# Persistent live USB user guide

RufusArm64 can create a persistent live USB for a deliberately narrow set of Ubuntu and Debian images.

## Use the persistent-media workflow

The **Create USB** button in the ordinary RufusArm64 writer performs a normal image write. For a Linux ISOHybrid image, it preserves the image byte-for-byte and therefore creates a non-persistent live USB.

RufusArm64 presents persistence in the main application window. Select the ISO and USB drive, expand **Persistent storage**, turn on saved changes, check compatibility, and use the same **Create USB** button. The restricted persistence helper remains separate internally so the ordinary writer does not silently gain persistence privileges.

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
- a direct root-self convenience alias such as the official Ubuntu 26.04 `ubuntu -> .` entry, which can be safely omitted;
- GPT/UEFI creation with one FAT32 boot partition and one ext4 persistence partition;
- at least 1 GiB of persistence storage.

Traditional Ubuntu configurations may contain `boot=casper`. Newer configurations may instead use a command such as `linux /casper/vmlinuz $cmdline ---`. RufusArm64 recognizes both forms and inserts `persistent` before the `---` separator while leaving unrelated kernel entries unchanged.

FAT32 cannot store Unix symbolic links. Safe in-tree links are therefore materialized as ordinary files or directories. A repository alias such as `dists/stable -> resolute` becomes a real `dists/stable` directory containing verified copies of the target files. Those duplicate files count toward entry, byte, FAT32-capacity, copy, and verification limits.

A root-level alias such as `ubuntu -> .` is different: copying it as a real directory would recursively duplicate the complete image. RufusArm64 therefore omits only a direct child of the media root that resolves exactly back to that root. Nested aliases back to the root, absolute or external links, directory cycles, device nodes, case-colliding paths, and unbounded expansions are refused.

Compressed images, virtual disks, MBR persistence, BIOS-only media, files too large for FAT32, encrypted persistence, and unrecognized boot layouts are refused. An unversioned derivative must include modern casper metadata; a kernel path alone is not enough to weaken the compatibility gate.

## Creation workflow

1. Open RufusArm64.
2. Choose the Ubuntu or Debian ISO.
3. Select the exact removable USB drive.
4. Choose how much space to keep for saved files and settings. Leave the value at zero to use the recommended available space.
5. Expand **Persistent storage**, enable saved changes, and select **Check compatibility**. This read-only check does not open or modify the USB.
6. When RufusArm64 reports that the image is supported, select the normal **Create USB** button.
7. Confirm the exact USB in the final erase warning, then keep it connected until creation completes.

Advanced options are collapsed by default. Most users should leave the USB name unchanged and leave development boot-time validation disabled. The privileged helper still repeats all source and target identity checks, removable-drive checks, filesystem verification, and final buffer flushing before reporting success.

After creation, boot from the USB, create a small test file in the live system's Home folder, restart from the same USB, and confirm that the file is still present. This simple reboot test is the practical confirmation that persistence works on that computer.

## Optional technical qualification after creation

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


## Development option: boot-time UEFI media validation

The privileged persistent-media helper accepts `--runtime-uefi-validation` for the ARM64 writable-copy path. It installs the package-owned, reproducibly built upstream `uefi-md5sum` loader transactionally, preserves the original fallback loader as `EFI/BOOT/bootaa64_original.efi`, and writes a verified root `md5sum.txt`. The current loader is unsigned; enabling this option does not establish Secure Boot compatibility. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not accept this option.
