# RufusArm64 0.16.0

## Highlights

RufusArm64 0.16.0 publishes the complete current ARM64 source line as one exact community release. It incorporates all post-0.15 work already merged and qualified by the repository, including:

- Rufus-style Linux ISO Image mode and exact DD Image mode;
- Windows ARM64 installation media with FAT32, NTFS, WIM splitting, UEFI:NTFS, guarded unattended setup, and capability-gated customisations;
- an experimental Windows 11 ARM64 Windows To Go path with direct NTFS deployment, GUID-bound BCD/ESP construction, mandatory SAN policy 4, first-boot customisations, and complete software readback;
- multi-architecture UEFI:NTFS structural verification, strict El Torito UEFI extraction, persistent Linux media, FreeDOS, data formatting, drive backup, checksums, bad-block testing, and bounded FFU restoration;
- device-identity binding, system-disk refusal, repeated pre-erasure validation, cancellation, flush, filesystem checking, and independent post-write verification.

## Qualification and support boundary

This is the latest public release, not a claim that every supported-looking combination has been physically booted. The exact source passes automated software, native ARM64, privileged loop-device, package, reproducibility, static-analysis, and vulnerability gates. Physical behavior still depends on the exact image, target medium, USB bridge/controller, firmware, Secure Boot state, machine, and operating-system setup path.

It is impossible for a small community project to boot every image on every firmware and architecture before publication. Features with narrower evidence are clearly marked experimental or bounded in the interface and documentation. Users should test on disposable removable media, keep unrelated storage disconnected for high-risk unattended paths, and report reproducible failures through GitHub Issues with non-sensitive diagnostics.

Windows To Go remains experimental because Microsoft removed official support and universal physical first-boot compatibility cannot be promised. FFU restoration remains limited to the documented single-store-v1 profile. The optional ARM64 runtime-integrity loader is unsigned; **Secure Boot compatibility is not established**. The built-in signed update channel remains disabled because production offline signing keys and public mirrors have not been provisioned.

Physical hardware testing remains a continuing community activity rather than a release blocker for every declared software path.

## Safety and support boundaries

Every media-creation operation can erase the complete selected target. Verify the exact model, serial, capacity, source, target identity, and operation summary before authentication. Never rely on `/dev/sdX` alone, and never test destructive or unattended behavior against storage containing needed data.

The four broad development trackers used before this release are being closed. Future work should be filed as narrowly scoped defects or concrete requests rather than permanent umbrella issues.

## Install and rollback

Verify the adjacent checksum sidecar:

```bash
sha256sum -c rufusarm64_0.16.0_arm64.deb.sha256
```

Install or upgrade:

```bash
sudo apt install ./rufusarm64_0.16.0_arm64.deb
```

Rollback to the previous package, if retained, with:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.15.0_arm64.deb
```

Rollback changes installed software only. It cannot undo USB media that has already been repartitioned or written.
