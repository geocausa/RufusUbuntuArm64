# Project status and qualification boundaries

_Last reviewed: 31 July 2026_

RufusArm64 is an independent Linux-native implementation of materially relevant Rufus-style bootable-media workflows for ARM64 systems. The parity baseline is pinned in `docs/upstream-rufus-parity.json`; a bounded Linux implementation is not described as universal upstream parity.

## Release channels

| Channel | Meaning |
| --- | --- |
| Tagged stable release | Immutable source and package artifacts associated with one reviewed Git tag. |
| Prerelease | A tagged release candidate intended for controlled qualification. |
| `main` | Current integrated development. It may be ahead of every public package and must not be represented as a published release. |
| Feature branch | Temporary review scope. Merged branches are deleted automatically; the pull request and commit history remain. |

## Current capability summary

| Area | Status | Boundary |
| --- | --- | --- |
| Raw/DD image writing | Implemented | Exact source and target identity, synchronization, and configured readback are enforced. |
| Linux ISO Image mode | Bounded implementation | Qualified ARM64 UEFI paths only; broader distribution-specific adaptations and universal firmware claims remain outside scope. |
| Windows installation media | Implemented for the documented layouts | Broader physical Windows Setup and firmware coverage remains a qualification task. |
| Windows Setup customisation | Substantial bounded implementation | Options are admitted only when the exact source proves the required capability. Silent installation has an additional disk-numbering guard and destructive warning. |
| Windows To Go | Experimental, software-qualified | Windows 11 client ARM64 GPT/UEFI/NTFS profile only. Physical firmware boot and Windows first boot are not yet claimed. |
| Linux persistence | Bounded implementation | Qualified Ubuntu casper and Debian live-boot paths; broader distribution and NTFS-persistence coverage remain incomplete. |
| UEFI runtime media validation | Software implemented | The optional ARM64 loader is unsigned; physical Secure Boot acceptance remains unqualified. |
| FFU | Experimental partial implementation | Single-store-v1 restore only; capture and broader profiles are not implemented. |
| Release/update trust | Software foundation implemented | Production offline-key ceremony, public signed catalogue, and mirror operations remain pending. |
| Localisation | Planned | The interface and accessibility review are not yet translation-complete. |

## Qualification language

- **Implemented** means the documented software path exists and passes its required repository checks.
- **Software-qualified** means the exact source tree passed the relevant unit, integration, loop-device, package, architecture, audit, and reproducibility gates.
- **Physically qualified** means an immutable candidate was exercised on identified hardware and firmware, with the result recorded separately.
- **Full upstream parity** requires materially relevant breadth as well as implementation. A narrow, safe subset is not full parity.

## Safety and release policy

1. No claim of bootability is derived solely from file-copy success or loop-device verification.
2. No destructive test is authorised by a stale `/dev/sdX` path. Exact identity, capacity, serial where available, transport, removable/hotplug state, and current kernel identity must be refreshed.
3. Internal/system disks are refused by normal workflows. Expert overrides are not a substitute for a reviewed test plan.
4. A public binary must correspond to an immutable tag and its documented release evidence.
5. Security-sensitive storage bypasses should be reported privately as described in `SECURITY.md`.

## Source of truth

- `README.md` — user-facing scope and operating guidance.
- `ROADMAP.md` — planned release programme and remaining work.
- `docs/upstream-rufus-parity.json` — feature-by-feature upstream comparison.
- `docs/operation-cost-contract.json` — source passes, writes, verification, temporary storage, and scaling contracts.
- `SECURITY.md` — privileged-operation trust boundaries and reporting guidance.
