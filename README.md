# RufusArm64

RufusArm64 is an **independent, unofficial bootable-USB creator for Ubuntu on ARM64 computers**, including Snapdragon X systems such as Surface Pro 11 X1E. It is a native Linux implementation inspired by Rufus; it is not a Wine wrapper and is not endorsed by the official Rufus project.

**Version 0.15.0** is the ISO Image mode parity and physical-qualification release candidate.

## Highlights

- Direct writing of recognized Linux ISOHybrid images and GPT/MBR raw disk images.
- A Rufus-style **ISO Image mode / DD Image mode** choice for suitable Linux ISOHybrid images, with conventional writable FAT32 extraction recommended by default and exact cloning retained as the alternative.
- Bounded Linux compatibility reporting for hybrid layouts, optical-only ISO media, El Torito BIOS/UEFI entries, and ISOLINUX/SYSLINUX/GRUB fingerprints.
- Safe preparation of ZIP, gzip, bzip2, XZ, LZMA, Zstandard, VHD, VHDX, QCOW2, and VMDK inputs.
- Windows installation media using GPT or MBR, UEFI or x86-family BIOS/CSM, and Automatic, FAT32, or NTFS selection.
- An explicit experimental **Windows To Go** GUI and CLI path for Windows 11 client ARM64, with exact edition-index binding, pre-authentication target geometry checks, direct NTFS image application, a GUID-bound FAT32 ESP/BCD, mandatory SAN policy 4, hash-bound first-boot customizations, and full loop-device readback while physical firmware boot remains unclaimed.
- Bounded Windows multi-edition reporting for WIM, ESD, and validated split SWM payloads before optional Setup customizations.
- A guarded graphical persistent Ubuntu casper and Debian live-boot workflow.
- A guarded **Restore / format…** workflow for verified data-only GPT/MBR media using FAT16, FAT32, exFAT, NTFS, UDF, ext2, ext3, or ext4.
- Fast deterministic **FreeDOS…** media creation from checksum-pinned, source-retained FreeDOS 1.4 and FreeCOM payloads for x86 BIOS or UEFI Legacy/CSM systems, with required-extent write/readback rather than capacity-scaled whole-device cloning.
- Explicit post-operation actions to create another USB or restore the exact completed target for ordinary storage.
- Threshold-signed and local-signed image-catalog verification, storage preflight, cancellation, SHA-256 installation, and resumable private partials.
- Descriptor-safe UEFI, DBX, and SBAT analysis plus optional ARM64 boot-time media-integrity validation for supported persistent media.
- A guarded **Save drive image…** workflow supporting verified raw, dynamic VHD, dynamic VHDX, and mounted-filesystem ISO/UDF capture without replacing existing files.
- An experimental authenticated FFU restore workflow for the supported single-store-v1 profile, with strict source evidence, target binding, complete readback, and explicit unsupported-profile refusal.
- Keyboard mnemonics, safe visible shortcuts, assistive-technology metadata, selectable status text, and exportable diagnostics.
- Whole-device, source-identity, target-identity, mount, system-disk, cancellation, filesystem, and post-copy verification safeguards.

## Install on Ubuntu ARM64

Verify the release-candidate checksum and install:

```bash
sha256sum -c rufusarm64_0.15.0_arm64.deb.sha256
sudo apt install ./rufusarm64_0.15.0_arm64.deb
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

## ISO Image mode and DD Image mode

For suitable Linux ISOHybrid images, RufusArm64 presents an explicit choice before destructive authorization:

- **Write in ISO Image mode (Recommended)** creates one conventional writable FAT32 partition and extracts the accepted ISO filesystem tree.
- **Write in DD Image mode** retains the existing exact byte-for-byte image writer, including the source image's embedded partition and boot structures.

ISO Image mode is offered only after bounded compatibility analysis confirms one strict, hash-bound UEFI path. A native architecture fallback loader may be present directly in the ISO tree or inside exactly one validated EFI no-emulation El Torito FAT image. The privileged helper repeats the source/catalog/image checks before erasure, mounts any extracted boot image read-only, merges it with the ISO tree only under multi-root path and collision validation, copies every admitted file transactionally, hashes every file back from the USB, checks the selected filesystem, and flushes the device. Unsupported or ambiguous images remain on the DD path when a coherent raw layout exists; RufusArm64 never silently converts an ISO-mode refusal into a destructive DD write.

Ordinary ISO Image mode does not enable persistence or modify boot configuration. Software and loop-device verification do not prove that every physical computer will boot the result; that is recorded separately in the 0.15.0 hardware checklist.

## Windows ARM64 media

For systems such as Surface Pro 11 X1E, use an official Windows ARM64 ISO with:

```text
GPT / UEFI / Automatic or FAT32
```

Windows ARM64 does not support legacy PC BIOS/CSM boot. x86 and x86-64 Windows media may use MBR/BIOS only when compatible boot files and `bootmgr` are present.

Before optional customizations, the exact source ISO is mounted read-only. Every installation edition must agree on Windows generation, client/server family, and architecture. The options dialog reports edition count/names plus WIM, ESD, or complete split-SWM payload type and part count. Conflicting or unknown metadata disables customizations but does not block ordinary no-customization media creation.

Automatic mode prefers FAT32 and splits oversized WIM/ESD payloads when required. NTFS uses the exact pinned Rufus 4.15 UEFI:NTFS image. In addition to its whole-image SHA-256, RufusArm64 structurally proves the embedded ARM32, ARM64, IA32, RISC-V64, and x64 fallback, NTFS, and exFAT loader triplets by exact FAT path, size, SHA-256, PE machine, and subsystem. `rufusarm64-cli uefi-ntfs inspect --json` reports that read-only evidence. Native FAT32 remains the most firmware-compatible ARM64 recovery path.

Optional Windows Setup changes include hardware-check bypass, offline/local account creation, privacy and regional settings, BitLocker suppression, driver loading, Quality of Life policies, installed-system SkuSiPolicy deployment, and qualified Windows UEFI CA 2023 bootloader replacement. Each option is capability-gated from the exact ISO and repeated by the privileged writer.

**Silent installation is deliberately narrower and high risk.** It is offered only for positively identified Windows 11 client media after exact WIM image indexes, boot.wim Setup language, no pre-existing unattended file, a local account, privacy choices, and regional settings have been established. Resolved UEFI/FAT32 and UEFI/NTFS media both add a verified 1 MiB `RUFUS_BOOT` partition as partition 2 so it can act as Rufus's disk-numbering guard. FAT32 continues to boot natively from partition 1; its partition 2 is not a UEFI:NTFS boot path. NTFS uses the same pinned image for both UEFI:NTFS bootstrapping and the guard. When the guard passes, Windows Setup may erase **disk 0**, create a fresh EFI/MSR/Windows layout, and install the selected image index without showing the normal disk or edition pages. The GUI requires a separate three-part acknowledgement; direct CLI use requires the literal `ERASE DISK 0`. Disconnect every other internal, external, card-reader, and removable storage device before booting such media. Software verification proves the generated media contract, not that a particular Windows installation will complete on physical hardware.


## Experimental Windows To Go

The Windows options dialog and direct CLI expose a deliberately narrow Windows To Go profile for positively identified Windows 11 client ARM64 media. It requires a 512-byte or 4 KiB-sector target of at least a nominal 32 GB class, the exact WIM image index reported by analysis, a GPT/UEFI layout, a 260 MiB unlabelled FAT32 EFI System Partition, and an NTFS Windows partition with at least 2 GiB of reviewed headroom beyond the image's expanded size.

The graphical selector is offered only when read-only ISO analysis proves Windows 11 client ARM64, complete exact image indexes, a positive expanded size, and a valid default language for every image. After an exact edition is selected, the chosen USB must independently pass the same capacity and 512-byte/4 KiB sector-geometry rules as the privileged backend. RufusArm64 accepts the Windows To Go first-boot choices that apply to an already-deployed system: online-account bypass, a local administrator, reduced data collection, Quality of Life changes, and locale/time-zone settings. Hardware-check bypass, silent installation, BitLocker suppression, SkuSiPolicy, CA 2023 replacement, drivers, DBX overrides, full format, and bad-block checking remain refused. The GUI displays the fixed layout and requires four acknowledgements covering whole-drive erasure, Microsoft's removal of Windows To Go support, the exact edition, and mandatory internal-disk isolation.

The writer uses the package-owned NTFS-enabled WIM engine to apply the selected image directly to the unmounted NTFS partition, preserving Windows-specific metadata through libntfs-3g's native volume path. RufusArm64 streams the engine's carriage-return progress records into the graphical and JSON progress channels, including an average expanded-data rate. It also snapshots the exact target's kernel `ioerr_cnt` before application and cancels with a dedicated failed-medium diagnostic if that counter changes or the device leaves the running state. If Linux remains trapped retrying the failed device for 45 seconds, the GUI explicitly instructs the user to disconnect only that selected target so the blocked writer and private mounts can be released. It constructs BCD transactionally from the applied image's own `BCD-Template`, binds the exact disk, ESP, and Windows partition GUIDs, disables recovery, and installs the Microsoft ARM64 fallback bootloader. Before erasure, the selected first-boot choices are combined with mandatory offline SAN policy 4 into one deterministic `Windows/Panther/unattend.xml`; its size and SHA-256 are bound into the reviewed plan, then the exact file is read back after creation. The Windows partition is marked not to receive a default drive letter, and both filesystems are reopened read-only and independently verified before success is reported.

Direct use requires all three explicit arguments:

```text
--mode windows-to-go
--experimental-windows-to-go
--win-to-go-confirm "CREATE EXPERIMENTAL WINDOWS TO GO"
```

and `--win-to-go-image-index N` for the exact selected edition. Optional first-boot flags are `--win-bypass-online-account`, `--win-local-user NAME`, `--win-reduce-data-collection`, `--win-quality-of-life`, `--win-locale LOCALE`, and `--win-timezone NAME`. Internal disks are always kept offline through SAN policy 4. This mode erases the complete target. Microsoft removed Windows To Go from supported modern Windows releases, and RufusArm64 has not yet observed this output booting through physical firmware or completing first boot. The software result therefore remains experimental and never reports firmware boot as verified. Encrypted-file restoration and Windows extended attributes remain upstream wimlib limitations.

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

Select a removable target and choose **Restore / format…**. RufusArm64 calculates an unprivileged identity-bound plan for GPT or MBR and FAT16, FAT32, exFAT, NTFS, UDF, ext2, ext3, or ext4. It displays geometry, required tools, warnings, and an exact `FORMAT` phrase before administrator authentication.

FAT16 is admitted only when the canonical whole-drive partition remains below 4 GiB; larger targets fail before erasure rather than being silently truncated. UDF uses a fixed stable 2.01 hard-disk profile, exact logical-sector blocks, descriptor and `blkid` agreement, closed-integrity evidence, and a private read-only kernel mount because Linux has no general UDF repair checker. ext2, ext3, and ext4 are created through distinct package-resolved formatter contracts and independently classified from their ext superblock features after a read-only `e2fsck`. A successful report verifies the partition geometry and exact filesystem generation. It does not claim bootability. Cancellation before erasure leaves the drive unchanged; cancellation or failure after erasure reports changed incomplete media conservatively.

## Create FreeDOS media

The **FreeDOS…** workflow creates deterministic FreeDOS 1.4 media from package-owned checksum-pinned payloads. It requires 512-byte logical sectors, an exact device identity/capacity, reviewed MBR/FAT32 geometry, and the phrase:

```text
WRITE FREEDOS 1.4 TO /dev/DEVICE FOR X86 BIOS LEGACY
```

The plan displays the exact required write and readback totals before authentication. Creation retains a nearly full-size FAT32 partition but writes and verifies only the final MBR, bounded head/tail clearing, FAT32 boot/FSInfo and reserved regions, both complete FAT tables, root directory, payload clusters, and allocation slack. Unallocated data clusters are intentionally untouched, so runtime scales with required filesystem structures rather than USB capacity.

A successful report confirms required-extent readback, the reviewed structure, and an extent-set SHA-256. It is not a whole-device health test; use **Check USB** for exhaustive write/readback qualification.

The resulting media targets **x86-compatible processors using BIOS or UEFI Legacy/CSM**. It is not for ARM64, UEFI-only, or Secure Boot-only systems. Software verification does not prove physical boot compatibility.

## Save a drive image

Select a removable drive and choose **Save drive image…**. RufusArm64 plans the destination without elevation, opens the source read-only through the package-owned helper, and atomically publishes only complete synchronized output. Existing files are never replaced and cancellation removes temporary output.

Raw backup preserves every reported source byte. Dynamic VHD and VHDX use a trusted descriptor-only `qemu-img` path and compare guest-visible bytes against the held source; VHDX also requires a successful non-repairing consistency check. Filesystem ISO/UDF capture remasters exactly one mounted filesystem through a private read-only bind view, then independently mounts the image as UDF and compares every admitted path, type, regular-file size, and file digest. ISO/UDF capture does not include partition tables, hidden sectors, unallocated space, additional filesystems, or a bootability guarantee.

## Experimental FFU restore

The FFU path is deliberately experimental and limited to the reviewed single-store-v1 full-flash profile. It verifies structural metadata, hash tables, catalog membership/signature chains, authorized publishers, complete source content, and a sealed target-bound plan before allowing the exact destructive confirmation. The helper then acquires the whole target exclusively, writes in the reviewed order, flushes, reads back, and verifies the complete restored content.

Unsupported FFU profiles, missing or untrusted catalog evidence, source mutation, target substitution, ambiguous capacity, protected/system disks, and incomplete verification fail closed. FFU capture remains unimplemented, and no vendor-device boot or recovery claim is made.

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

Software checks never establish universal physical boot, persistence, whole-device health, or Secure Boot compatibility. Complete the human checklist in `docs/hardware-checklist-0.15.0.md` before public release.

## Build and test

Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, `qemu-utils`, `genisoimage`, the verified ARM64 WIM engine, and source-retained package-private boot assets.

```bash
./scripts/test.sh
```

Run the versioned Linux ISO compatibility corpus against locally downloaded official images with:

```bash
PYTHONPATH=gui python3 scripts/linux_iso_corpus.py \
  --image-dir "$HOME/Downloads" \
  --helper /usr/lib/rufusarm64/rufusarm64-helper \
  --allow-missing
```

See `docs/linux-iso-corpus.md` for the qualification boundary and `docs/linux-iso-corpus.json` for immutable artifact identities and pending representatives.

The release-candidate package is produced at:

```text
dist/rufusarm64_0.15.0_arm64.deb
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

- `docs/release-0.15.0.md` for release notes, boundaries, installation, and rollback;
- `docs/hardware-checklist-0.15.0.md` for the mandatory real-machine GO/NO-GO record;
- `docs/persistence-qualification.md` for exact persistence evidence;
- `docs/freedos-user-guide.md` for the FreeDOS boundary.

Rollback to the previous package with:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.14.0_arm64.deb
```

Rollback does not repair USB media already written. Use the guarded restoration workflow only after selecting and confirming the exact removable target.

## License

RufusArm64 is GPL-3.0-or-later. Rufus is a separate GPL-licensed project by Pete Batard and contributors. No official status or endorsement is claimed.
