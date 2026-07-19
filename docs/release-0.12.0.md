# RufusArm64 0.12.0

RufusArm64 0.12.0 is the clean Stage 1 ARM64 release. It adds a guarded read-only drive-image backup workflow and includes a focused code audit of the new privilege, process, reporting, packaging, and release paths.

## Highlights

- Select a removable drive and use **Save drive image…** to create a byte-for-byte image on another physical disk.
- Review an unprivileged plan containing the exact source path, identity, capacity, destination directory, required bytes, and available bytes before authentication.
- Require the exact `SAVE /dev/DEVICE TO /absolute/path/image.img` confirmation phrase.
- Stream validated progress, throughput, ETA, cancellation state, final path, and SHA-256 through the graphical workflow.
- Publish no final pathname until copy, synchronization, source and destination revalidation, and desktop-user ownership handoff succeed.
- Retain the existing ordinary writer, persistent-live creator, destructive USB qualification, Windows media, UEFI analysis, and reproducible package gates.

## Audit corrections

The pre-release audit found and corrected three material edge cases. The authenticated backup helper now refuses a destination directory unless the desktop user has write and search permission there without elevation. A broken JSON progress channel cancels and removes temporary output before publication. Exceptional graphical parsing or lifecycle failures now terminate, drain, escalate, and reap only the owned `pkexec` process group before the main window is released from its busy state.

Report parsing is also fail-closed: successful reports cannot carry failures, failed or cancelled reports require complete failure records, byte accounting remains exact integer data, and graphical success requires a matching zero exit status, regular-file type, exact size, and desktop-user ownership.

## Safety and support boundaries

Drive-image capture opens the selected source read-only, but mounted source filesystems may be unmounted briefly to produce a coherent snapshot. The destination must be a new pathname on another physical disk, and existing files or symbolic links are never replaced. A streaming SHA-256 is reported after successful synchronized capture; this is not a substitute for retaining important independent backups.

The optional package-owned ARM64 UEFI runtime-integrity loader remains unsigned. Secure Boot compatibility is not established. It remains limited to the guarded persistent writable-copy workflow and is not exposed by raw-image, Windows, NTFS, compressed-stream, or virtual-disk writers.

Physical hardware testing remains separate from software, loop-device, native ARM64 runner, reproducibility, and QEMU evidence. This release is suitable for field play-testing, and hardware-specific observations will be corrected through 0.12.x patches while Stage 2 proceeds toward 0.13.0.

## Install and rollback

Install or upgrade on Ubuntu ARM64 with:

```bash
sudo apt install ./rufusarm64_0.12.0_arm64.deb
```

Verify the downloaded package first with its published SHA-256 sidecar. To remove the package without deleting images or other user-created files:

```bash
sudo apt remove rufusarm64
```

Rollback is performed by reinstalling a previously retained package version with the Debian package manager. Existing drive images are user data and are not removed by upgrade, rollback, or package removal.

## Supply-chain and release assets

The canonical `v0.12.0` release workflow publishes the ARM64 Debian package, checksum sidecar, deterministic project source archive, pinned WIM corresponding source, and deterministic `uefi-md5sum` corresponding source from the exact synchronized release commit. The unsigned EFI wrapper remains package-private rather than being published as a standalone boot binary.
