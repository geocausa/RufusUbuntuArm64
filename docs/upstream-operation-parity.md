# Upstream Rufus operation parity

RufusArm64 is a native Linux implementation, not a line-for-line Windows port. The implementation may differ, but the ordinary user's operation should match upstream Rufus unless a reviewed Linux constraint requires otherwise.

This document defines the review method that prevents a safe and well-tested implementation from doing materially more work than the corresponding Rufus operation.

The machine-readable source of truth is [`operation-cost-contract.json`](operation-cost-contract.json). `internal/operationcost` validates it in the normal Go test suite.

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
| Raw/ISOHybrid writing | One pre-write source hash plus the source read that writes the image | Optional physical target hash compared with the authenticated write digest; no third source read | Conformant plain-source path after #254; prepared-input hand-off remains in #253 |
| Compressed image preparation | Container plus complete expanded raw staging | Raw writer contract | Audit in #242 |
| Virtual-disk preparation | Container plus complete virtual-size raw staging | Raw writer contract | Audit in #242 |
| Restore / format | Partition and filesystem metadata | Filesystem structural checks | Conformant |
| Windows full format | Partition capacity, explicitly selected | Flush before filesystem creation | Conformant explicit maintenance |
| Windows bad-block check | Partition capacity, explicitly selected | Complete zero-pattern readback | Conformant explicit qualification |
| Check USB quick | Distributed bounded samples | Sample readback | Conformant explicit qualification |
| Check USB full | Complete target capacity | Complete address-pattern readback | Conformant explicit qualification |
| Save drive image | Complete target capacity | Atomic image publication | Conformant imaging operation |
| Verified acquisition | Download size | Signed metadata and SHA-256 | Conformant |

## Upstream reference pin

The current parity record reviews `pbatard/rufus` at commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`, principally `src/format.c`, `src/drive.c`, and `src/wue.c`.

The pin is evidence of what was reviewed, not a permanent claim that Rufus never changes. Refreshing it requires examining changed upstream defaults and updating the operation matrix deliberately.

## Audit order

The current priority is:

1. Windows installation-media source consistency and its three complete ISO hashes.
2. Persistent Linux source hashing versus manifest-bound copy verification.
3. Compressed and virtual-image full staging.
4. Raw writer source-pass reduction.
5. A complete upstream default-options comparison.

Optimisation must preserve target identity binding, cancellation, pre-erasure source binding, truthful changed-media reporting, synchronized finalisation, and exact verification claims.
