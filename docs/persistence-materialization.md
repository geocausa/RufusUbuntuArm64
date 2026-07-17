# Linux persistence materialization primitives

The 0.9 development line separates persistence creation into auditable steps. The public CLI remains read-only, but the internal `persistence` package now provides three write-ready primitives for a future privileged orchestration layer.

## 1. Exact partition-plan application

`ApplyPartitionPlan` consumes an already-open target descriptor, the original image size, actual target size, and the previously generated `Plan`.

Before changing any bytes, it rebuilds the plan from the target's current partition metadata and requires an exact match. This prevents a plan generated from one image or capacity from being applied after the target changes.

For MBR it:

- requires the selected primary slot to remain empty;
- writes a Linux filesystem (`0x83`) entry with 32-bit LBA bounds;
- preserves the boot signature and verifies the written entry.

For GPT it:

- revalidates both existing headers and entry tables;
- creates a Linux filesystem data entry with a cryptographically random unique GUID;
- moves the backup entry table and header to the actual end of the target;
- updates the primary and protective MBR geometry;
- writes and syncs the new backup before changing the primary;
- verifies both new headers, tables, CRCs, and persistence extent;
- clears the obsolete backup metadata only after the new GPT pair is durable.

The function writes partition metadata only. It does not ask the kernel to reread the table or format a partition.

## 2. Symlink-resistant boot-tree patching

`PatchBootTree` is intended for a writable copy of supported live-media files. It does not operate on an ISO9660 mount.

It only touches paths returned by the bounded detector and only changes kernel-argument lines that already contain the matching `boot=casper` or `boot=live` marker. Existing `persistent`/`persistence` arguments are left unchanged.

For every file it:

- pins the tree root and parent directory descriptors;
- rejects non-local paths and symbolic-link components;
- opens the original final component with `O_NOFOLLOW`;
- limits the file to the detector's 1 MiB text bound and requires UTF-8;
- writes a same-directory temporary file, preserves permissions, and fsyncs it;
- rechecks the original device/inode before atomic rename;
- fsyncs the parent directory after replacement.

This design avoids path traversal and symlink-following attacks. The future orchestrator must additionally ensure that the writable media tree is private and cannot be modified by another process during creation.

## 3. Ext4 filesystem initialization

`CreateFilesystem` accepts the already-created partition path, exact plan, expected kernel device ID and size, and a final caller safety callback.

It:

- rejects symlinks and non-block devices;
- opens the partition with `O_NOFOLLOW`, takes an advisory exclusive `flock`, and keeps the parent whole-disk lock for the complete operation;
- verifies the open device identity and exact planned capacity;
- passes the partition to tools through an inherited `/proc/self/fd/3` descriptor instead of reopening the user-supplied path;
- deliberately does not hold the partition with kernel `O_EXCL`, because `mkfs`, `mount`, and filesystem checkers must reopen the inherited descriptor path and would otherwise fail with `EBUSY`;
- runs `mkfs.ext4` with the exact `casper-rw` or `persistence` label and eager metadata initialization;
- mounts with `nosuid,nodev,noexec`;
- creates Debian's root `persistence.conf` as `/ union` using no-follow exclusive creation;
- fsyncs, unmounts, and runs `e2fsck -f -n` before success.

Cancellation after mounting triggers a bounded cleanup unmount. The caller must keep the parent whole-disk lock for the entire operation.

## Why this is not enabled yet

RufusUbuntuArm64 currently writes Linux ISOHybrid images in raw mode. On common Ubuntu and Debian images the boot configuration remains inside a read-only ISO9660 filesystem, so appending an ext4 partition alone would not reliably activate persistence.

The next required tranche is a Linux ISO extraction/copy mode that:

1. mounts the identity-bound ISO read-only;
2. creates a writable boot partition using a supported filesystem and bootloader layout;
3. copies files through bounded, no-follow source traversal;
4. applies the boot-tree patches;
5. creates and verifies the persistence partition;
6. verifies copied files and bootability on real ARM64 hardware.

Until that orchestration and hardware matrix exist, the GUI and `write` command do not offer persistence creation.
