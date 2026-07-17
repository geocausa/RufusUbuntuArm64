# RufusArm64

RufusArm64 is an **independent, unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X devices such as Surface Pro 11 X1E. It is a native Linux implementation inspired by Rufus; it is not a Wine wrapper and is not endorsed by the official Rufus project.

## Highlights

- Direct writing of recognized Linux ISOHybrid images and GPT/MBR raw disk images.
- Safe preparation of ZIP, gzip, bzip2, XZ, LZMA, Zstandard, VHD, VHDX, QCOW2, and VMDK inputs.
- Windows installation media using GPT or MBR, UEFI or x86-family BIOS/CSM, and Automatic, FAT32, or NTFS selection.
- Native FAT32 UEFI media with automatic WIM/ESD splitting, plus checksum-pinned Rufus UEFI:NTFS support.
- Optional Windows Setup customizations, driver staging, and Microsoft Secure Boot DBX scanning.
- Signed image-catalog verification, threshold-root channel foundations, rollback protection, and checksum-gated downloads.
- A dedicated guarded graphical workflow for persistent Ubuntu casper and Debian live-boot USB media.
- Whole-device, source-identity, target-identity, mount, system-disk, cancellation, filesystem, and post-copy verification safeguards.

## Install on Ubuntu ARM64

```bash
sudo apt install ./rufusarm64_0.10.2_arm64.deb
```

The package upgrades older `rufusarm64` installations in place. Open **RufusArm64** or **RufusArm64 Persistent Live USB** from the application menu afterward.

## Create ordinary boot media

1. Connect a removable USB drive.
2. Choose an ISO, raw image, supported compressed image, or supported virtual disk.
3. Select the exact USB device.
4. For Windows media, review the partition scheme, target system, filesystem, and optional Setup choices.
5. Keep copied-file verification enabled for qualification runs.
6. Select **Create USB**, verify the destructive warning, and authenticate.

Everything on the selected USB is permanently erased.

The **Create USB** button in the main RufusArm64 window always performs the ordinary image-writing workflow. It does not turn a live ISO into persistent media. Use the separately installed **RufusArm64 Persistent Live USB** application for persistence.

## Persistent Linux media

Version 0.10.2 includes a separate graphical **Persistent Live USB** wizard. It currently supports a deliberately narrow contract:

- plain raw-bootable ISOHybrid media;
- Ubuntu 20.04+ casper or Debian live-boot;
- GPT/UEFI;
- an architecture-matching fallback loader in `EFI/BOOT`;
- a FAT32-compatible live-media tree;
- bounded in-tree file and directory symbolic links that can be safely materialized as ordinary FAT32 entries;
- a writable FAT32 boot partition and separate ext4 persistence partition;
- at least 1 GiB of persistence capacity.

Ubuntu media use the `persistent` kernel parameter and ext4 label `casper-rw`. Debian media use `persistence`, ext4 label `persistence`, and a root `persistence.conf` containing `/ union`.

### Modern Ubuntu casper layouts

RufusArm64 accepts both traditional commands containing `boot=casper` and newer commands that identify the live kernel structurally, for example:

```text
linux /casper/vmlinuz $cmdline --- quiet splash
```

For the structural form, the analyzer also requires modern casper metadata such as `casper/install-sources.yaml`. The patcher inserts `persistent` before `---`, changes only detector-approved kernel lines, and rechecks the copied boot tree afterward. Unversioned derivatives without sufficient metadata remain refused.

### Persistence workflow

1. Open **RufusArm64 Persistent Live USB**, not the ordinary writer.
2. Select the Linux ISO and exact removable USB.
3. Choose a persistence size; zero uses the suitable remaining space.
4. Run **Analyze selected image**. This identity-bound step mounts only the ISO read-only and never opens the USB device.
5. Review the detected family, filesystem label, boot parameter, fresh GPT layout, required FAT32 capacity, and boot files to be changed.
6. Confirm **Erase and create persistent USB**.
7. Keep the drive connected while data are copied, flushed, and checked. Slow flash drives may spend several minutes committing cached writes.

Persistence analysis and creation intentionally ignore the ISO's embedded hybrid MBR geometry. Like upstream Rufus, the creator builds a fresh target GPT containing a writable FAT32 boot partition and a separate ext4 persistence partition, then copies and verifies the approved live-media tree.

Relative directory links used by Debian/Ubuntu repository metadata, such as `dists/stable`, are copied as real directories because FAT32 has no symbolic-link representation. Their files are hashed, counted again for capacity planning, copied through the same verified path, and rehashed on the destination. Absolute links, links outside the ISO, cycles, device nodes, and unbounded expansions remain refused.

Creation is not final qualification. Boot the USB and run:

```bash
sudo rufusarm64-cli qualify start \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-initial.json"
```

Make a harmless persistent change, reboot the same USB, confirm the change survived, then run:

```bash
sudo rufusarm64-cli qualify verify \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-verified.json"
```

A passing report qualifies only that exact ISO, USB, controller, firmware, and computer for the observed reboot. It is not a universal firmware guarantee.

Compressed images, virtual disks, MBR/BIOS persistence, encrypted persistence, oversized FAT32 files, unknown boot layouts, bootloader replacement, kernel/initramfs replacement, and major distribution upgrades remain outside this persistence contract.

See `docs/persistence-user-guide.md` and `docs/persistence-qualification.md`.

## Windows ARM64 media

For systems such as Surface Pro 11 X1E, use an official Windows ARM64 ISO with:

```text
GPT / UEFI / Automatic or FAT32
```

Automatic prefers FAT32 and splits a large Windows installation payload. NTFS is available through the pinned UEFI:NTFS loader, but native FAT32 remains the most firmware-compatible recovery path. Windows ARM64 does not support legacy PC BIOS/CSM boot.

x86 and x86-64 media may additionally use MBR/BIOS when the ISO contains compatible boot files and a root `bootmgr`.

## Safety model

The privileged helpers:

- accept only whole block devices beneath `/dev`;
- refuse partitions, read-only devices, and the disk backing the running system;
- hide internal MMC/eMMC and normal fixed disks from the default list;
- bind the selected source and target to refreshed identities;
- hash the already-open source before destructive work and recheck it later;
- revalidate the target immediately before destructive phases;
- reject unsafe symbolic-link traversal while allowing only bounded in-tree materialization for FAT32 live-media copying;
- hold target locks, flush block buffers, verify copied files, and check filesystems;
- require fresh Polkit authorization and support protected cancellation.

No private acquisition signing key is included in source, CI, packages, or artifacts. The production built-in acquisition channel remains disabled until reviewed offline trust metadata is provisioned.

## Build and test

Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, and the verified ARM64 WIM engine under `vendor/wimlib/arm64/`.

```bash
./scripts/test.sh
```

The installer is produced at:

```text
dist/rufusarm64_0.10.2_arm64.deb
```

## Command-line examples

```bash
rufusarm64-cli list
rufusarm64-cli inspect --image Windows.iso.xz --json
rufusarm64-cli acquire channel list --json
rufusarm64-cli persistence plan \
  --image ubuntu.iso --media-root /mnt/ubuntu \
  --target-size 64G --size 16G --json
sudo rufusarm64-cli write \
  --mode linux-persistent --experimental-persistence \
  --image ubuntu.iso --device /dev/sdX --persistence-size 16G
```

The graphical applications supply device-identity binding, exact confirmation, and protected cancellation automatically and are recommended for normal use.

## License

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
