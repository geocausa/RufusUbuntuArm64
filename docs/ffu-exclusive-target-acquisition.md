# FFU exclusive target acquisition

Status: **kernel-exclusive target capability without mutation**. This document does not authorize restoration.

Tracking issue: #277  
Live target preflight: #307  
Authenticated source lease: #308

## Purpose

The FFU source can now be authenticated and held stable under a mandatory Linux read lease. The selected removable target can also be rediscovered and reviewed against live Linux state. The next independent boundary is acquiring the exact target descriptor without exposing any operation that can change it.

`AcquireExclusiveFullFlashTarget` accepts the sealed authenticated source lease and the exact reviewed live target preflight. The target must already be fully unmounted. Mounted targets remain outside this tranche because guarded unmounting changes host state and requires its own transaction and failure model.

## Linux open boundary

The production acquisition opens the exact reviewed path with:

```text
O_RDWR | O_EXCL | O_NOFOLLOW
```

`O_EXCL` is the Linux kernel exclusivity boundary for the block-device descriptor. An additional advisory `flock` is deliberately not used: it would be redundant for this purpose and is rejected by Linux loop devices in existing qualification paths.

The acquisition then requires:

- the authenticated source lease to remain held and healthy;
- the source identity to remain exact;
- exact agreement between source-lease evidence and the reviewed target preflight;
- target preflight to contain no mounted descendants and no unmount requirement;
- successful kernel-exclusive, no-follow, read/write target open;
- live descriptor identity and capacity verification through `BLKGETSIZE64`;
- current whole-disk/removable/system-disk policy revalidation with fixed-disk permission disabled;
- unchanged target identity token, capacity, and kernel device identity;
- no target mounts appearing during acquisition;
- unchanged logical and physical sector geometry from sysfs;
- continued FFU store-block compatibility; and
- proof that the held source descriptor is not stored on the selected target or one of its descendants.

The source lease and target descriptor are checked again after all live discovery checks before the capability is issued.

## Sealed non-mutating capability

`FullFlashTargetSession` owns the target descriptor and carries an unexported capability seal. It exposes only:

- independently owned deterministic evidence;
- an explicit health recheck; and
- idempotent close.

It exposes no target descriptor, file descriptor, read, write, positional I/O, seek, sync, or ioctl method. Future mutation code must remain within `internal/ffu` and must consume a separately reviewed execution-authorization capability.

Closing the target session closes only the target descriptor. It deliberately does not release the caller-owned authenticated source lease.

## Deterministic evidence

A successful acquisition binds:

- source-lease, target-preflight, full-flash-validation, target-plan, and authenticated-integrity SHA-256 identifiers;
- exact target path and expected/rediscovered identity tokens;
- target capacity, logical and physical sector geometry, and FFU store block size;
- expected and observed kernel device identities and current `major:minor`;
- exact mutation-byte scope from the reviewed plan;
- healthy source-lease state;
- read/write, kernel-exclusive, no-follow target-open states;
- absence of mounted target components;
- explicit non-performance of guarded unmounting;
- descriptor, policy, geometry, and source-location verification states;
- permanent fixed-disk override refusal;
- target-access acquisition without mutation authority;
- warnings and limitations; and
- an outer deterministic SHA-256.

The plan advances:

- `target_access_acquired: true`.

It retains:

- `mutation_permitted: false`;
- `execution_supported: false`.

## Rechecking

`FullFlashTargetSession.Check` verifies:

1. the source lease and complete source identity;
2. the open target descriptor identity and capacity;
3. the current `/dev` path and whole-disk safety policy;
4. unchanged target identity and kernel device identity;
5. absence of mounts;
6. unchanged sector geometry; and
7. continued separation between the source filesystem and target disk.

Any failure invalidates the capability. No recovery, substitution, or fixed-disk fallback is permitted.

## Remaining provider boundary

This tranche deliberately performs no:

- guarded target unmount;
- administrator or Polkit command exposure;
- explicit destructive confirmation consumption;
- execution authorization;
- FFU payload or GPT phase writing;
- cancellation/changed-media result state;
- synchronized flush;
- target readback or descriptor verification after mutation;
- loop-device restore execution;
- GTK integration; or
- physical boot claim.

The acquired descriptor is necessary but still insufficient for restoration. A later execution boundary must bind the exact confirmation, source lease, target session, write ordering, verification scope, cancellation semantics, and changed-media reporting before any byte can be modified.
