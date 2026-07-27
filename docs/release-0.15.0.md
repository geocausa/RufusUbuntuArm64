# RufusArm64 0.15.0 development notes

Status: Stage 4 development branch; not a published release.

## Completed software tranches

- Guarded ext2 and ext3 data-only formatting through the existing GPT/MBR planner, exact identity binding, exact `FORMAT` confirmation, e2fsprogs creation, forced read-only `e2fsck -f -n`, exact filesystem/geometry/label readback, GTK integration, and real loop-device qualification.
- Application-scoped GTK appearance selection with canonical **System**, **Light**, and **Dark** modes.

## Appearance contract

- **System** is the default and restores the GTK light/dark preference observed when RufusArm64 started.
- **Light** and **Dark** affect only the current RufusArm64 process and its dialogs.
- The canonical setting is stored in the existing owner-private settings JSON as `appearance: system|light|dark`.
- Missing, malformed, and unknown values resolve to **System**.
- The selector is exposed from the main header bar with tooltips and assistive-technology metadata.
- Appearance changes do not alter device/image identities, destructive confirmation, privilege separation, cancellation, verification, synchronization, or reports.

## Remaining Stage 4 scope

- Translation-catalog extraction and translation-aware accessibility review.
- Remaining portable distribution and filesystem work admitted by the pinned parity audit.
- UDF formatting remains excluded until a Linux-native post-format checker satisfies the formatter's read-only verification contract.
- ReFS remains non-portable without a verified Linux-native formatter.
- Windows To Go remains deferred.

All feature PRs remain gated on exact-head Go 1.22, native ARM64, static/vulnerability, privileged-loop, package, reproducibility, UEFI, FreeDOS, and formatter qualification workflows.
