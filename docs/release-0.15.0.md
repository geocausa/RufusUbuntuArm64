# RufusArm64 0.15.0

## Highlights

RufusArm64 0.15.0 is the ISO Image mode parity and physical-qualification release candidate for Ubuntu ARM64.

- Suitable Linux ISOHybrid images now present a Rufus-style **ISO Image mode / DD Image mode** choice.
- **ISO Image mode (Recommended)** is selected by default when the image and target pass the bounded compatibility analysis.
- ISO Image mode creates conventional writable MBR/FAT32 UEFI media rather than cloning the source image's fixed partition layout.
- The existing DD writer remains available as the explicit byte-for-byte alternative and stays automatic for images outside the reviewed extraction scope.
- The privileged creator repeats source, target, UEFI, FAT32, path, file-size, collision, capacity, and geometry checks before erasure; then it copies transactionally, reads every file back by SHA-256, checks FAT32, and flushes the target.
- Target locking tolerates only short-lived expected contention through a bounded cancellable retry and continues to fail closed on sustained or unexpected contention.
- A dedicated privileged qualification writes through the production backend, detaches and reopens the completed image, probes FAT32 independently, mounts it read-only, and compares copied content.

Existing DD writing, Windows media creation, persistent Linux media, data-only formatting, FreeDOS, USB qualification, drive backup, checksums, UEFI analysis, and the experimental FFU boundary remain available.

## Prerelease purpose and physical testing

Physical hardware testing remains required before 0.15.0 is promoted from prerelease to stable. The candidate checklist is `docs/hardware-checklist-0.15.0.md`.

The central physical observation is an Ubuntu ARM64 ISOHybrid written with ISO Image mode on the intended Surface Pro 11 ARM64 host. The record must show the choice dialog, ISO mode selected by default, successful creation and verification, actual UEFI boot, and ordinary writable FAT32 behavior. A bounded DD-mode regression should also be recorded where practical.

Software, CI, and loop-device passes do not establish universal physical boot, firmware, controller, flash-health, Secure Boot, distribution, or vendor compatibility.

## ISO Image mode boundary

ISO Image mode currently accepts a plain raw-bootable Linux ISOHybrid image whose complete accepted tree can be represented by one FAT32 partition and which contains the architecture fallback UEFI loader, such as `EFI/BOOT/BOOTAA64.EFI` on ARM64.

It refuses unsupported or unsafe sources before target mutation, including missing fallback loaders, compressed or virtual-disk input, optical-only media, FAT32-incompatible paths, case-insensitive collisions, files at or above FAT32's single-file boundary, escaping or cyclic links, unsupported sector geometry, insufficient target capacity, source mutation, target substitution, and protected/system disks.

An ISO-mode refusal is not proof that an image is corrupt. DD Image mode remains the exact-clone alternative. RufusArm64 does not silently start DD writing after an ISO-mode refusal; the user must explicitly choose and confirm the alternative.

Ordinary ISO Image mode does not patch boot configuration or enable persistence. Persistent media remains a separate explicit workflow.

## Safety and support boundaries

Every media-creation path can destroy all accessible data on the selected target. Confirm the exact device path, model, capacity, source identity, target identity, chosen write mode, and generated confirmation before authentication.

The package-owned ARM64 `uefi-md5sum` loader remains unsigned. **Secure Boot compatibility is not established** for that optional persistent-media wrapper. ISO Image mode itself does not claim Secure Boot acceptance merely because a fallback loader is structurally present.

The production built-in acquisition channel remains disabled until reviewed public mirrors, offline root-key operations, and a signed catalogue are provisioned. FFU restoration remains experimental and narrowly scoped; FFU capture is not implemented. Windows To Go remains deferred.

## Verification and release construction

The exact candidate must pass Go 1.22 compatibility, unit/race/shuffle coverage, vet, static and vulnerability checks, native ARM64 execution, packaged-binary execution, the dedicated ISO Image mode reopened-loop qualification, existing privileged loop regressions, Lintian/AppStream/desktop validation, WIM/UEFI reproduction, and byte-for-byte Debian package reproducibility.

The canonical stable workflow will publish:

- `rufusarm64_0.15.0_arm64.deb`;
- `rufusarm64_0.15.0_arm64.deb.sha256`;
- the corresponding deterministic source and required corresponding-source archives.

A separate explicitly marked prerelease uses Debian version `0.15.0~rc1`, which sorts before stable `0.15.0`.

## Install and rollback

Verify the package checksum:

```bash
sha256sum -c rufusarm64_0.15.0_arm64.deb.sha256
```

Install or upgrade:

```bash
sudo apt install ./rufusarm64_0.15.0_arm64.deb
```

To roll back to 0.14.0, keep its package and run:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.14.0_arm64.deb
```

Rollback does not repair USB or block devices already modified by a newer release.
