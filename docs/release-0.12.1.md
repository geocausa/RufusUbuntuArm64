# RufusArm64 0.12.1

RufusArm64 0.12.1 is a focused Stage 1 patch release for a field-reported graphical startup failure in 0.12.0.

## Highlights

- Pins GTK 3 in the installed isolated launcher before importing the integrated qualification and drive-image dialogs.
- Prevents systems that also expose GTK 4 introspection from selecting the wrong namespace before the main application requests GTK 3.
- Adds an executable launcher-order regression for the exact packaged Python payload.
- Retains all 0.12.0 writer, persistence, qualification, UEFI-analysis, and drive-image backup behavior unchanged.

## Safety and support boundaries

This patch changes only graphical startup ordering. It does not alter privileged commands, source or target identity checks, destructive confirmation, filesystem operations, image-writing behavior, or drive-image publication.

The optional package-owned ARM64 UEFI runtime-integrity loader remains unsigned. Secure Boot compatibility is not established. Physical hardware testing remains separate from software, loop-device, native ARM64 runner, reproducibility, and QEMU evidence.

## Install and rollback

Install or upgrade on Ubuntu ARM64 with:

```bash
sudo apt install ./rufusarm64_0.12.1_arm64.deb
```

Verify the package first with the published SHA-256 sidecar. Remove it with `sudo apt remove rufusarm64`. Rollback by reinstalling a retained 0.12.0 package; user-created USB media and drive images are not removed by package upgrade, rollback, or removal.

## Supply-chain and release assets

The canonical `v0.12.1` workflow publishes `rufusarm64_0.12.1_arm64.deb`, its checksum sidecar, deterministic project source, pinned WIM corresponding source, and deterministic `uefi-md5sum` corresponding source from the exact synchronized release commit.
