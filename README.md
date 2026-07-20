# RufusArm64

RufusArm64 is an **independent, unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X devices such as Surface Pro 11 X1E. It is a native Linux implementation inspired by Rufus; it is not a Wine wrapper and is not endorsed by the official Rufus project.

## Highlights

- Direct writing of recognized Linux ISOHybrid images and GPT/MBR raw disk images.
- Safe preparation of ZIP, gzip, bzip2, XZ, LZMA, Zstandard, VHD, VHDX, QCOW2, and VMDK inputs.
- Windows installation media using GPT or MBR, UEFI or x86-family BIOS/CSM, and Automatic, FAT32, or NTFS selection.
- Native FAT32 UEFI media with automatic WIM/ESD splitting, plus checksum-pinned Rufus UEFI:NTFS support.
- Optional Windows Setup customizations, driver staging, and Microsoft Secure Boot DBX scanning.
- Signed image-catalog verification, threshold-root channel foundations, rollback protection, and checksum-gated downloads.
- A guarded graphical workflow for persistent Ubuntu casper and Debian live-boot USB media, exposed through the single RufusArm64 application entry.
- Descriptor-safe UEFI, DBX, and SBAT analysis plus optional ARM64 boot-time media-integrity validation for the supported persistent writable-copy path.
- A guarded **Save drive image…** workflow that captures a selected removable drive read-only into a new SHA-256-reported image without replacing existing files.
- Whole-device, source-identity, target-identity, mount, system-disk, cancellation, filesystem, and post-copy verification safeguards.

## Install on Ubuntu ARM64

```bash
sudo apt install ./rufusarm64_0.12.1_arm64.deb
```

The package upgrades older `rufusarm64` installations in place. One visible **RufusArm64** application entry is installed. Its normal launch opens the ordinary writer, and its **Create Persistent Live USB** desktop action opens the guarded persistence wizard.

## Create ordinary boot media

1. Connect a removable USB drive.
2. Open **RufusArm64** normally.
3. Choose an ISO, raw image, supported compressed image, or supported virtual disk.
4. Select the exact USB device.
5. For Windows media, review the partition scheme, target system, filesystem, and optional Setup choices.
6. Keep copied-file verification enabled for qualification runs.
7. Select **Create USB**, verify the destructive warning, and authenticate.

Everything on the selected USB is permanently erased.

The **Create USB** button in the ordinary writer always performs the normal image-writing workflow. It does not turn a live ISO into persistent media.

## Persistent Linux media

Version 0.12.1 retains the separate guarded persistence wizard internally while presenting only one desktop application icon. Open it from the same RufusArm64 application entry using the **Create Persistent Live USB** action. The direct command remains available for troubleshooting:

```text
rufusarm64 --persistence
```

The wizard currently supports a deliberately narrow contract:

- plain raw-bootable ISOHybrid media;
- Ubuntu 20.04+ casper or Debian live-boot;
- GPT/UEFI;
- an architecture-matching fallback loader in `EFI/BOOT`;
- a FAT32-compatible live-media tree;
- bounded in-tree file and directory symbolic links that can be safely materialized as ordinary FAT32 entries;
- harmless direct root-self aliases such as the official Ubuntu 26.04 `ubuntu -> .` link, which are omitted rather than recursively copied;
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

1. Open the **Create Persistent Live USB** action from the RufusArm64 application entry, or run `rufusarm64 --persistence`.
2. Select the Linux ISO and exact removable USB.
3. Choose a persistence size; zero uses the suitable remaining space.
4. Optionally select **Validate media at UEFI boot**. The current package-owned ARM64 loader is unsigned, so Secure Boot compatibility is not established.
5. Run **Analyze selected image**. This identity-bound step mounts only the ISO read-only and never opens the USB device; changing the option afterward requires analysis again.
6. Review the detected family, filesystem label, boot parameter, fresh GPT layout, required FAT32 capacity, and boot files to be changed.
7. Confirm **Erase and create persistent USB**.
8. Keep the drive connected while data are copied, flushed, and checked. Slow flash drives may spend several minutes committing cached writes.

Persistence analysis and creation intentionally ignore the ISO's embedded hybrid MBR geometry. Like upstream Rufus, the creator builds a fresh target GPT containing a writable FAT32 boot partition and a separate ext4 persistence partition, then copies and verifies the approved live-media tree.

Relative directory links used by Debian/Ubuntu repository metadata, such as `dists/stable`, are copied as real directories because FAT32 has no symbolic-link representation. Their files are hashed, counted again for capacity planning, copied through the same verified path, and rehashed on the destination. A direct root-self alias such as `ubuntu -> .` is omitted because reproducing it on FAT32 would require recursively duplicating the complete image. Nested links back to the media root, links outside the ISO, cycles, device nodes, and unbounded expansions remain refused.

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

Compressed images, virtual disks, MBR/BIOS persistence, encrypted persistence, oversized FAT32 files, unknown boot layouts, arbitrary bootloader replacement, kernel/initramfs replacement, and major distribution upgrades remain outside this persistence contract. The only fallback-loader wrapping is the explicit, transactional ARM64 runtime-integrity option described below.

See `docs/persistence-user-guide.md` and `docs/persistence-qualification.md`.


### Optional boot-time UEFI media validation

For compatible ARM64 persistent writable-copy media, the wizard can transactionally preserve the image's original `EFI/BOOT/BOOTAA64.EFI` as `EFI/BOOT/bootaa64_original.efi`, install the package-owned `uefi-md5sum` wrapper, and generate a verified root `md5sum.txt`. At boot, the wrapper checks the covered media tree and then chainloads the original fallback loader.

The canonical loader is built twice from pinned `uefi-md5sum` v1.2 and EDK2 commits and accepted only when the binaries and provenance are byte-for-byte identical. It is **unsigned**. Secure Boot compatibility is not established, and the option is off by default. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not expose it.

The unchanged-media and intentional-corruption paths, including original-loader chainload, are qualified under pinned AArch64 QEMU firmware. That evidence does not replace physical qualification of the exact USB, controller, firmware, Secure Boot state, and computer.

## Windows ARM64 media

For systems such as Surface Pro 11 X1E, use an official Windows ARM64 ISO with:

```text
GPT / UEFI / Automatic or FAT32
```

Automatic prefers FAT32 and splits a large Windows installation payload. NTFS is available through the pinned UEFI:NTFS loader, but native FAT32 remains the most firmware-compatible recovery path. Windows ARM64 does not support legacy PC BIOS/CSM boot.

x86 and x86-64 media may additionally use MBR/BIOS when the ISO contains compatible boot files and a root `bootmgr`.

## Save a drive image

Select a removable drive and choose **Save drive image…** to create a byte-for-byte image on another physical disk. RufusArm64 plans the destination without elevation, displays the exact source identity and capacity, requires the exact `SAVE /dev/DEVICE TO /absolute/path/image.img` phrase, and then uses the package-owned read-only helper through Polkit.

The final pathname appears only after the full source capacity is copied, synchronized, SHA-256 accounted, source and destination are revalidated, and ownership is handed to the desktop user. Existing files are never replaced. Cancellation and failures remove incomplete temporary output. The authenticated helper refuses destination directories in which the desktop user could not create a file without elevation.

This workflow is read-only with respect to the source, but mounted source filesystems may be unmounted briefly for a coherent snapshot. **Create USB** and **Check USB…** remain separate operations and are disabled while capture is active.

## Safety model

The privileged helpers:

- accept only whole block devices beneath `/dev`;
- refuse partitions, read-only targets, and the disk backing the running system;
- hide internal MMC/eMMC and normal fixed disks from the default list;
- bind the selected source and target to refreshed identities;
- hash the already-open source before destructive work and recheck it later;
- revalidate the target immediately before destructive phases;
- reject unsafe symbolic-link traversal while allowing only bounded in-tree materialization and the explicit omission of a direct root-self alias for FAT32 live-media copying;
- hold target locks, flush block buffers, verify copied files, and check filesystems;
- require fresh Polkit authorization and support protected cancellation.

No private acquisition signing key is included in source, CI, packages, or artifacts. The production built-in acquisition channel remains disabled until reviewed offline trust metadata is provisioned.

## Build and test

Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, the verified ARM64 WIM engine under `vendor/wimlib/arm64/`, and the reproducible package-private ARM64 `uefi-md5sum` artifact under `vendor/uefi-md5sum/arm64/`. Regenerating the loader additionally requires the pinned EDK2 toolchain dependencies documented in `docs/uefi-md5sum-build.md`.

```bash
./scripts/test.sh
```

The installer is produced at:

```text
dist/rufusarm64_0.12.1_arm64.deb
```

## Command-line examples

```bash
rufusarm64-cli list
rufusarm64-cli inspect --image Windows.iso.xz --json
rufusarm64-cli hash --all ubuntu.iso
rufusarm64-cli acquire channel list --json
rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --firmware-sbat --json
rufusarm64-cli uefi integrity manifest --directory /mnt/usb > md5sum.txt
rufusarm64-cli uefi integrity verify --directory /mnt/usb --json
rufusarm64-cli persistence plan \
  --image ubuntu.iso --media-root /mnt/ubuntu \
  --target-size 64G --size 16G --json
sudo rufusarm64-cli write \
  --mode linux-persistent --experimental-persistence \
  --image ubuntu.iso --device /dev/sdX --persistence-size 16G
```

The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The selected-image **Checksums…** action calculates MD5, SHA-1, SHA-256, and SHA-512 through the unprivileged descriptor-bound helper without changing writer state; MD5 and SHA-1 are legacy comparison values only. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, DBX, and SBAT results, and can compare against either a trusted local SbatLevel CSV or the running shim firmware SBAT level without changing the write path.

That pre-boot structural/Secure Boot analysis is separate from the boot-time media-integrity option. Version 0.12.1 also provides descriptor-safe manifest generation and verification through the unprivileged CLI and an opt-in transactional ARM64 wrapper in the guarded persistent-media workflow; the wrapper is unsigned and is not offered by other writer modes.

## License

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
