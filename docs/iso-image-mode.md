# ISO Image mode

RufusArm64 offers a Rufus-style choice for suitable Linux ISOHybrid images:

- **Write in ISO Image mode (Recommended)** is selected by default.
- **Write in DD Image mode** remains available as the exact byte-for-byte alternative.

The choice appears only when read-only inspection identifies a strict, hash-bound UEFI path. The fallback loader may be exposed directly by the ISO tree or by exactly one validated EFI no-emulation El Torito FAT image. Ambiguous, unsupported, or hash-incomplete catalogue evidence does not enable ISO Image mode.

## What ISO Image mode does

ISO Image mode creates conventional writable ARM64 UEFI media and extracts the supported ISO media tree onto it. Compatible media can use a reviewed MBR or GPT layout, **Automatic**, **FAT32**, or **NTFS**, a 4, 8, 16, or 32 KiB cluster size, and an editable per-image label. Target system remains capability-bound to validated UEFI rather than becoming a cosmetic selector.

Automatic is the recommended default. It inspects the complete media tree and:

- selects FAT32 when every path and file can be represented safely; or
- selects NTFS only when FAT32 is incompatible and all NTFS/UEFI:NTFS requirements pass before erasure.

Before erasing the USB, the privileged helper:

1. binds the exact source-file identity and exact removable target identity;
2. holds the source read-only with a Linux kernel lease when available, otherwise uses conservative repeated SHA-256 passes;
3. mounts the image privately and read-only;
4. inventories and hashes the complete ISO media tree;
5. requires the native fallback UEFI loader, such as `EFI/BOOT/BOOTAA64.EFI` on ARM64, or extracts the exact single validated El Torito UEFI image to an owner-only file and verifies its catalogue, image, and plan SHA-256 identities;
6. mounts any extracted El Torito FAT image read-only with `nosuid,nodev,noexec`, verifies the loop source and mount flags, and merges its tree with the ISO tree only when exact and case-folded paths do not conflict;
7. checks the selected filesystem's filename, case-collision, reserved-name, symlink, single-file-size, total-size, cluster, and target-capacity constraints;
8. admits the exact pinned 1 MiB UEFI:NTFS image when NTFS is selected; and
9. revalidates the selected source and target immediately before the destructive boundary.

Only after those checks pass does it create the selected layout, format through a held partition descriptor, copy each file transactionally, hash every copied file back from the USB, run a read-only filesystem check, and flush the device.

FAT32 uses one FAT32 data partition. NTFS uses one NTFS data partition plus the exact verified UEFI:NTFS boot partition. Primary and backup GPT metadata are both written and read back when GPT is selected. The UEFI:NTFS partition is compared completely with the pinned image after the kernel rereads the partition table.

Ordinary ISO Image mode does **not** modify boot configuration or enable persistence. Persistent live media remains a separate explicit workflow, and NTFS persistence is not enabled by this feature.

## Visible layout choices

For compatible Linux ISOHybrid media, the main window exposes:

- MBR or GPT;
- Automatic, FAT32, or NTFS;
- 4, 8, 16, or 32 KiB clusters; and
- an editable per-image label.

Automatic and FAT32 use the reviewed FAT32 label boundary. Explicit NTFS permits the reviewed 32-character ASCII label boundary. The label resets to `RUFUS-LIVE` when a different image is selected, preventing a stale Windows label from leaking into Linux media. DD Image mode ignores all extraction-layout controls.

## When ISO Image mode is refused

The helper stops before erasure when the image cannot be represented within the reviewed scope. Examples include:

- no native ARM64 UEFI fallback loader in either the ISO tree or one unambiguous EFI no-emulation El Torito FAT image;
- an explicit FAT32 selection with a file above FAT32's single-file boundary;
- unsafe or incompatible FAT32 or NTFS names;
- exact or case-insensitive collisions between the ISO tree and an El Torito overlay, or within the target filesystem;
- NTFS reserved DOS or metadata names;
- a symbolic link that escapes the mounted media tree or creates a traversal cycle;
- a missing, modified, or wrong-size UEFI:NTFS image;
- an unsupported target sector, cluster, or partition geometry;
- insufficient USB capacity; or
- source or target identity changing after review.

A refusal is not evidence that the image is corrupt. The user can return to the choice dialog and select DD Image mode when an exact clone is appropriate.

## DD Image mode

DD Image mode uses the existing hardened raw writer. It preserves the image's embedded partition table, filesystems, boot records, and fixed image capacity byte-for-byte. It remains the automatic path for hybrid images that are not safely eligible for ISO extraction. ISO-mode filesystem, cluster, partition, and label controls never affect DD output.

## Qualification boundary

Software tests cover Automatic selection, strict El Torito plan/refusal publication, FAT32 and NTFS path policy, multi-root overlay collision refusal, MBR/GPT metadata and readback, descriptor-bound FAT32/NTFS formatting, exact UEFI:NTFS asset admission and comparison, complete copied-file verification, cancellation and identity refusal, cleanup, and real MBR/GPT FAT32/NTFS plus fallback-only El Torito loop-device creation. The loop workflow detaches and reopens every completed backing image before independent filesystem, file-tree, boot-partition, and GPT checks.

A new immutable release candidate still requires physical ARM64 firmware-boot evidence for ISO Image mode. Earlier DD-mode and persistence qualification does not automatically qualify this new extraction path.
