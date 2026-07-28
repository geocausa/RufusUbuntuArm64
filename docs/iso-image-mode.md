# ISO Image mode

RufusArm64 offers a Rufus-style choice for suitable Linux ISOHybrid images:

- **Write in ISO Image mode (Recommended)** is selected by default.
- **Write in DD Image mode** remains available as the exact byte-for-byte alternative.

The choice appears only when read-only inspection identifies an ISOHybrid image with a validated UEFI boot entry. Images outside that boundary continue through their existing automatic path without a misleading choice.

## What ISO Image mode does

ISO Image mode creates one conventional, writable FAT32 partition and extracts the supported ISO media tree onto it. The first implementation tranche is deliberately bounded to media that can be represented safely as ARM64 UEFI/FAT32 removable media.

Before erasing the USB, the privileged helper:

1. binds the exact source-file identity and exact removable target identity;
2. holds the source read-only with a Linux kernel lease when available, otherwise uses conservative repeated SHA-256 passes;
3. mounts the image privately and read-only;
4. inventories and hashes the complete media tree;
5. requires the native fallback UEFI loader, such as `EFI/BOOT/BOOTAA64.EFI` on ARM64;
6. checks FAT32 filename, case-collision, symlink, single-file-size, total-size, and target-capacity constraints; and
7. revalidates the selected source and target immediately before the destructive boundary.

Only after those checks pass does it create an active MBR FAT32-LBA partition, format it through a held partition descriptor, copy each file transactionally, hash every copied file back from the USB, run a read-only FAT32 consistency check, and flush the device.

Ordinary ISO Image mode does **not** modify boot configuration or enable persistence. Persistent live media remains a separate explicit workflow.

## When ISO Image mode is refused

The helper stops before erasure when the image cannot be represented within the reviewed scope. Examples include:

- no native UEFI fallback loader;
- a file at or above FAT32's 4 GiB single-file boundary;
- unsafe or incompatible filenames;
- case-insensitive FAT32 path collisions;
- a symbolic link that escapes the mounted media tree or creates a traversal cycle;
- an unsupported target sector geometry;
- insufficient USB capacity; or
- source or target identity changing after review.

A refusal is not evidence that the image is corrupt. The user can return to the choice dialog and select DD Image mode when an exact clone is appropriate.

## DD Image mode

DD Image mode uses the existing hardened raw writer. It preserves the image's embedded partition table, filesystems, boot records, and fixed image capacity byte-for-byte. It remains the automatic path for hybrid images that are not safely eligible for ISO extraction.

## Qualification boundary

Software tests cover planning, MBR readback, descriptor-bound FAT32 formatting, complete copied-file verification, cleanup, and refusal paths. A new release candidate still requires physical ARM64 firmware-boot evidence for ISO Image mode. Earlier DD-mode and persistence qualification does not automatically qualify this new extraction path.
