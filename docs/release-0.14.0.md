# RufusArm64 0.14.0

## Highlights

RufusArm64 0.14.0 is the Stage 3 advanced imaging and recovery release candidate for Ubuntu ARM64.

- **Save drive image…** now supports four deliberately separate outputs: byte-exact raw, dynamic VHD, dynamic VHDX, and mounted-filesystem ISO/UDF.
- Raw/VHD/VHDX capture retains exact whole-device identity and capacity. VHD/VHDX use a trusted descriptor-only converter and compare guest-visible content against the held source; VHDX additionally requires a successful consistency check.
- ISO/UDF capture authenticates one mounted filesystem, creates a private read-only `ro,nosuid,nodev,noexec` source view, masters with fixed policy, independently mounts the private image as UDF, compares every supported path/type/regular-file-size/content digest, rehashes it, and publishes without replacement.
- A guarded **experimental FFU restore** path supports the reviewed single-store-v1 profile with structural validation, authenticated hash/catalog evidence, publisher authorization, source leases, target-bound plans, exact confirmation, exclusive target acquisition, ordered writes, and complete readback verification.
- USB qualification results can be exported as private identity-bound JSON evidence without replacing existing files.
- Compressed-image preparation reports bounded container progress and reserves 100% for the point at which complete source authentication has succeeded.
- Read-only El Torito UEFI extraction and the opt-in Rufus 4.15 Windows 11 setup Quality of Life policy extend compatibility work without enabling unsafe automatic paths.

Existing ordinary Linux/Windows writing, persistence, FreeDOS, data-only formatting, acquisition, checksums, UEFI/DBX/SBAT analysis, cancellation, identity, and verification paths remain available.

## Prerelease purpose and physical testing

Physical hardware testing remains required before 0.14.0 is promoted from prerelease to stable. The candidate checklist is `docs/hardware-checklist-0.14.0.md`.

The prerelease is intended to collect bounded observations for:

- installing and launching the ARM64 Debian package;
- raw, VHD, VHDX, and ISO/UDF capture from representative removable media;
- opening produced containers/images with independent tools;
- cancellation and existing-destination refusal;
- experimental FFU dry-run/refusal behavior and, only with disposable supported media, complete restore/readback;
- existing Ubuntu ARM64, Windows ARM64, persistence, FreeDOS, data-formatting, and USB qualification regressions.

A software pass is not a universal hardware, firmware, controller, flash-health, FFU-device, or bootability certification.

## Drive-backup boundaries

Raw capture is a byte-for-byte whole-device image. Dynamic VHD and VHDX preserve the exact reported source capacity inside sparse containers, but no particular sparse-size saving is promised.

Filesystem ISO/UDF capture is not a whole-disk image. It captures exactly one admitted mounted filesystem and excludes partition tables, boot records, hidden sectors, unallocated space, other filesystems, unsupported names/types, symlinks, hard links, and mount crossings. Successful content verification does not establish bootability.

Existing destination paths are never replaced. A failed or cancelled operation removes private temporary output unless an unmount failure requires preserving a root-owned workspace as evidence.

## Experimental FFU boundary

FFU restoration remains experimental and intentionally narrow. Only the reviewed single-store-v1 full-flash profile is accepted. The source must satisfy the complete structural, hash-table, catalog-member, signature-chain, publisher-authorization, trust-metadata, content, and target-bound plan policy before destructive authorization can be sealed.

Unsupported profiles, missing trust material, unrecognized publishers, source mutation, target substitution, capacity mismatch, protected mounts, system disks, ambiguous device identities, and incomplete verification fail closed. FFU capture is not implemented. No Surface, OEM recovery, firmware boot, or cross-vendor deployment claim is made.

## Safety and support boundaries

Every ordinary write, persistence creation, restore/format, FreeDOS creation, qualification, or FFU restore can destroy all accessible data on the selected target. Confirm the device path, model, capacity, source identity, target identity, and generated phrase before authentication.

The package-owned ARM64 `uefi-md5sum` loader remains unsigned. **Secure Boot compatibility is not established** for that optional persistent-media wrapper.

The production built-in acquisition channel remains disabled until reviewed public mirrors, offline root-key operations, and a signed catalogue are provisioned. No private signing key is included in the repository, CI, package, or release artifacts.

Windows To Go remains deferred. FFU capture, encrypted persistence, arbitrary bootloader replacement, unsupported FFU profiles, and universal physical boot or media-health claims remain outside this release.

## Verification and release construction

The exact candidate must pass Go 1.22 compatibility, race/shuffle/unit coverage, vet, static analysis, vulnerability checks, native ARM64 execution, packaged-binary execution, privileged raw/VHD/VHDX/ISO-UDF qualification, FFU software audit, formatter and FreeDOS qualification, Lintian/AppStream/desktop validation, WIM/UEFI reproduction, and byte-for-byte Debian package reproducibility.

The canonical stable tag workflow will publish:

- `rufusarm64_0.14.0_arm64.deb`;
- `rufusarm64_0.14.0_arm64.deb.sha256`;
- the corresponding RufusArm64 source archive;
- the pinned wimlib source archive;
- the pinned uefi-md5sum source archive and checksum.

A separate, explicitly marked prerelease may use a Debian version that sorts before 0.14.0 so the stable package remains a normal upgrade.

## Install and rollback

Verify the package checksum:

```bash
sha256sum -c rufusarm64_0.14.0_arm64.deb.sha256
```

Install or upgrade:

```bash
sudo apt install ./rufusarm64_0.14.0_arm64.deb
```

Existing settings are retained. The package upgrades earlier RufusArm64 installations in place.

To roll back to 0.13.0, keep its package and run:

```bash
sudo apt install --allow-downgrades ./rufusarm64_0.13.0_arm64.deb
```

To remove RufusArm64 while retaining normal user files:

```bash
sudo apt remove rufusarm64
```

Rollback does not repair USB or block devices already modified by a newer release.
