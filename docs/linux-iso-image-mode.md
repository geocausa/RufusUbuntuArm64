# Linux ISO Image mode and DD Image mode

RufusArm64 can offer two write methods for a supported Linux ISOHybrid image.

## ISO Image mode — recommended default

When the selected image and USB pass the read-only compatibility check, RufusArm64 selects **Write in ISO Image mode (Recommended)** by default.

ISO Image mode:

- creates a fresh GPT partition table;
- creates one conventional writable FAT32 EFI System Partition;
- privately mounts the selected ISO read-only;
- inventories and hashes every accepted file before erasing the USB;
- requires the architecture-specific removable-media fallback UEFI loader, such as `EFI/BOOT/BOOTAA64.EFI` for ARM64;
- copies every accepted file from the ISO filesystem tree;
- reads the copied files back and verifies their SHA-256 digests;
- checks the completed FAT32 filesystem and flushes the USB before reporting success.

This mode is convenient for ordinary firmware access and permits the remaining FAT32 space to be used normally. It does **not** reproduce the ISOHybrid image byte-for-byte.

## DD Image mode — exact copy

DD Image mode preserves the complete image exactly, including its embedded partition table, boot sectors, filesystem structures and unused regions within the image.

Choose DD Image mode when:

- an exact clone is required;
- the image's publisher specifically recommends raw/DD writing;
- ISO Image mode is unavailable;
- the image contains files or path names that FAT32 cannot represent;
- the image relies on an embedded boot layout that extraction cannot safely reproduce.

A DD-written USB can expose unusual, small or read-only partitions. This is expected because the USB inherits the image's original disk layout.

## Compatibility check

Before offering ISO Image mode, RufusArm64 performs a privileged but read-only analysis. The analyser accepts the selected image identity and the USB capacity, but it does not receive or open the USB device path.

ISO Image mode currently requires:

- a plain, uncompressed Linux ISOHybrid image;
- a recognized raw-bootable optical filesystem;
- a fallback UEFI loader matching the host architecture;
- a complete tree representable on FAT32;
- no file larger than FAT32's single-file limit;
- no unsafe symbolic links, traversal, case-insensitive collisions or unsupported entries;
- enough USB capacity for the copied data, FAT32 allocation overhead and safety headroom.

Compressed images, virtual disks, optical-only images and unsupported trees remain available through DD mode where applicable.

## Selection and safety

When both methods are available, the choice window defaults to ISO Image mode. DD mode remains visible as the alternative.

When ISO Image mode is unavailable, RufusArm64 explains why and offers DD mode only through a separate dialog whose default action is **Cancel**. It never silently switches a requested ISO extraction operation into DD writing.

Both destructive paths retain the normal RufusArm64 safeguards: exact source and target identity binding, final target revalidation after confirmation, running-system and protected-disk refusal, cancellation, synchronization and bounded completion reporting.

## Persistence

ISO Image mode by itself does not create persistent live storage. Use the separate **Persistent storage** option for supported Ubuntu or Debian live media. That workflow creates its own verified GPT/FAT32/ext4 layout and qualification record.

## Firmware qualification

Successful software creation and verification do not prove that every computer firmware will boot the USB. Test the completed media on the intended computer before depending on it for recovery or installation.
