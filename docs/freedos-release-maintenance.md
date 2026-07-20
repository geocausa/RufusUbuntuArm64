# FreeDOS release maintenance contract

This record defines the release and source-distribution obligations for the narrow FreeDOS 1.4 media path. It is planning evidence only. It does not add a command, device executor, Polkit action, package installation rule, runtime dependency, or GTK option.

The machine-readable contract is `vendor/freedos/RELEASE-CONTRACT.json`. Tests require every listed file, byte count, SHA-256 value, installation destination, update rule, and aggregate size to remain synchronized with the repository.

## Update policy

FreeDOS payload updates are intentional maintenance events, never unattended updates.

An update may begin only when the project deliberately adopts an official FreeDOS release or a security-relevant correction. The input must be the official checksum-pinned FullUSB archive. Runtime downloads, background refreshes, mutable mirrors, and host execution of DOS or x86 payloads are outside the contract.

For each update, the maintainer must:

1. verify the published FullUSB archive SHA-256;
2. reproduce the exact nested FreeCOM and kernel package members and hashes;
3. prove the `FORCELBA` derivation from primary kernel source and require that only the reviewed byte changes;
4. compare the final `COMMAND.COM` and `KERNEL.SYS` objects with the deliberately selected Rufus reference;
5. retain complete corresponding FreeCOM and kernel source archives plus exact package metadata and GPLv2 text;
6. regenerate all manifest sizes, hashes, Git object identities, and source pins;
7. pass payload, boot-code, deterministic builder, ordinary-file tamper, and read-only loop-device qualification tests;
8. produce two byte-identical Debian packages through the reproducible package gate;
9. review release notes and the BIOS/Legacy x86-only disclosure before any product exposure.

Failure at any step blocks the update. There is no fallback to an unverified download or a previous mutable cache.

## Package-impact measurement

The current reviewed material is small and bounded:

| Material | Uncompressed bytes |
| --- | ---: |
| Media payload written to the target (`COMMAND.COM` and configured `KERNEL.SYS`) | 134,028 |
| All embedded payload and boot assets, including the original kernel used to prove derivation | 182,181 |
| Complete corresponding FreeCOM and kernel source archives | 1,776,157 |
| Retained package metadata and GPLv2 text | 19,885 |
| Minimum uncompressed package material | 1,978,223 |

The minimum total excludes Go code, tests, documentation, archive/container overhead, and compression effects. The reproducible package job remains the authority for the final `.deb` byte delta. Any future implementation must record both the uncompressed installed delta and the compressed package delta before release approval.

## Runtime and installation boundary

A future implementation may compile the reviewed payload and boot assets into one package-private ARM64 helper at `/usr/lib/rufusarm64/rufusarm64-freedos-format`. The DOS payload must not be installed as separately executable files or searched for through the host `PATH`.

The current contract adds no runtime dependency. Construction and verification are native Go operations; loop qualification uses CI-only Ubuntu tools. A future production helper must not acquire payloads over the network and must not execute the x86 bytes on the ARM64 host.

Complete corresponding sources and metadata must accompany any package that exposes the feature:

- `/usr/share/doc/rufusarm64/freedos/source/freecom-sources.zip`;
- `/usr/share/doc/rufusarm64/freedos/source/kernel-sources.zip`;
- `/usr/share/doc/rufusarm64/freedos/metadata/FREECOM.LSM`;
- `/usr/share/doc/rufusarm64/freedos/metadata/KERNEL.LSM`;
- `/usr/share/doc/rufusarm64/freedos/metadata/KERNEL-COPYING`.

The Debian copyright record must identify the upstream FreeDOS and FreeCOM components, their GPLv2 terms, the retained complete corresponding sources, the source-backed one-byte kernel configuration derivation, and the GPL provenance of the embedded `ms-sys` boot-code assets. Packaging tests must reject missing, renamed, altered, or incorrectly installed source and licence material.

## Release gate

Release maintenance is supportable under this contract, but it does not authorize device writing. The remaining implementation gate is a dedicated identity-bound executor with root-disk refusal, exact confirmation, descriptor locking, final pre-destructive revalidation, guarded cancellation, media-changed reporting, synchronization, and complete byte-for-byte readback.

Terminal and GTK exposure remain blocked until that executor passes ordinary-file, real-loop, package, privilege, and cancellation gates. Physical boot success remains a separate evidence claim on representative x86 BIOS/Legacy hardware.
