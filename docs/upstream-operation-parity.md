# Upstream Rufus operation parity

RufusArm64 is a native Linux implementation, not a line-for-line Windows port. The implementation may differ, but the ordinary user's operation should match upstream Rufus unless a reviewed Linux constraint requires otherwise.

This document defines the review method that prevents a safe and well-tested implementation from doing materially more work than the corresponding Rufus operation.

The machine-readable sources of truth are [`operation-cost-contract.json`](operation-cost-contract.json) for byte-scaled work and [`upstream-default-contract.json`](upstream-default-contract.json) for ordinary defaults. `internal/operationcost` and `internal/defaultparity` validate them in the normal Go test suite.

## Review questions

Every destructive or long-running workflow must answer all of these before merge:

1. What is the corresponding upstream Rufus operation and default?
2. How many complete source passes occur?
3. How many bytes are written to the target?
4. How many target bytes are read back?
5. How much temporary storage is required?
6. Which verification is default, optional, or a separate qualification operation?
7. Does runtime scale with payload size, image size, partition capacity, or target capacity?
8. What is intentionally different on Linux, and why is that difference worth its cost?

An extra complete pass must protect a named correctness or threat property. “More verification” is not sufficient by itself when the same property can be obtained through a bounded extent check, a stable source snapshot, or an explicitly selected qualification workflow.

## Capacity-scaling rule

Ordinary creation must not write or read unused target capacity by default.

Capacity-scaled work is valid when the operation is explicitly one of the following:

- full USB qualification;
- bad-block checking;
- non-quick/full formatting;
- saving a complete drive image;
- restoring a raw disk image whose source itself contains every byte to write.

FreeDOS, Windows file-copy creation, persistent Linux file-copy creation, quick formatting, and verified downloading must scale with their required metadata or payload—not with empty space on a larger USB drive.

## Current matrix

| Operation | Scaling boundary | Default verification | State |
|---|---|---|---|
| FreeDOS creation | Required MBR/FAT32/payload extents | Required extents read back | Conformant after #240 |
| Windows installation media | Copied setup payload plus one complete ISO hash under a kernel read lease; two extra hashes only on conservative fallback | Optional copied-file verification | Conformant software path after #243 |
| Persistent Linux media | Copied media tree plus one complete source-image hash under a kernel read lease; two extra hashes only on conservative fallback | Manifest-bound destination verification | Conformant software path after #251 |
| Raw/ISOHybrid writing | One pre-write source hash plus the source read that writes the image, with a Linux read lease excluding concurrent mutation when available | Optional physical target hash compared with the authenticated write digest; no third source read | Conformant after #257 |
| Sequential compressed image preparation | One container read that also authenticates it, one private expanded write, one prepared-raw read for target writing | Authenticated expanded digest plus optional physical target verification | Conformant after #253 |
| ZIP image preparation | One complete ZIP hash plus extraction, one private expanded write, one prepared-raw read for target writing | Authenticated expanded digest plus optional physical target verification | Conformant after #253 |
| Virtual-disk preparation | One complete container hash plus qemu conversion, one converted-raw binding read, one prepared-raw read for target writing | Authenticated converted digest plus optional physical target verification | Conformant after #253 |
| Restore / format | Partition and filesystem metadata | Filesystem structural checks | Conformant |
| Windows full format | Partition capacity, explicitly selected | Flush before filesystem creation | Conformant explicit maintenance |
| Windows bad-block check | Partition capacity, explicitly selected | Complete zero-pattern readback | Conformant explicit qualification |
| Check USB quick | Distributed bounded samples | Sample readback | Conformant explicit qualification |
| Check USB full | Complete target capacity | Complete address-pattern readback | Conformant explicit qualification |
| Save drive image | Complete target capacity | Atomic image publication | Conformant imaging operation |
| Verified acquisition | Download size | Signed metadata and SHA-256 | Conformant |

## Upstream reference pin

The current parity record reviews `pbatard/rufus` at commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`, principally `src/rufus.c`, `src/format.c`, `src/drive.c`, and `src/wue.c`.

The pin is evidence of what was reviewed, not a permanent claim that Rufus never changes. Refreshing it requires examining changed upstream defaults and updating the operation matrix deliberately.

## Default-options matrix

| Default | Upstream Rufus source | Upstream | RufusArm64 | State |
|---|---|---|---|---|
| Post-write target verification | `src/rufus.c` ordinary Start path; validation remains separately selected | Off | Off on fresh CLI and GTK profiles | Conformant after #258 |
| Quick format | `src/rufus.c:EnableQuickFormat`; `src/format.c:FormatThread` | On | On | Conformant |
| Bad-block testing | `src/rufus.c` advanced-format controls; `src/format.c:WriteDrive` | Off | Off | Conformant |
| Windows partition scheme | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image/target | Automatic resolves GPT for UEFI media and MBR for proven BIOS-only x86/x64 media; explicit GPT/MBR retained | Conformant after #260 |
| Windows target system | `src/rufus.c:SetPartitionSchemeAndTargetSystem` | Derived from image | Automatic resolves UEFI from standard fallback loaders and BIOS only from root bootmgr plus bounded x86/x64 boot.wim metadata | Conformant after #260 |
| Windows filesystem | `src/rufus.c:SetFileSystemAndClusterSize` | FAT32 preferred, NTFS when required | FAT32 preferred, NTFS when FAT32 is unsafe | Conformant |
| Cluster size | `src/rufus.c:SetClusterSizes` | Filesystem/target default | Formatter automatic | Conformant |
| Persistence | `src/rufus.c` persistence controls | Off, size zero | Off, size zero | Conformant |
| Windows setup customizations | `src/wue.c` option dialog | Off until selected | Off until selected | Conformant |
| Raw/ISOHybrid handling | `src/format.c:WriteDrive` | Preserve embedded layout | Preserve embedded layout | Conformant |
| Volume label | `src/rufus.c:SetProposedLabel` | Proposed from image | Static `RUFUSARM64` unless edited | Intentional visible divergence; no destructive or compatibility impact |

The checked-in `upstream-default-contract.json` turns the high-risk rows into regression assertions. A fresh profile may not silently enable verification, full formatting, bad-block testing, persistence, or a concrete Windows layout.

## Audit order

The operation-cost audit completed these passes in order:

1. Windows installation-media source consistency.
2. Persistent Linux source hashing versus manifest-bound copy verification.
3. Compressed and virtual-image staging.
4. Raw writer source-pass reduction.
5. The complete upstream default-options comparison recorded above.

Optimisation must preserve target identity binding, cancellation, pre-erasure source binding, truthful changed-media reporting, synchronized finalisation, and exact verification claims.
