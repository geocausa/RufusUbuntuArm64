# FFU read-only target preflight

Status: **live Linux discovery and policy validation only**. This document does not define or authorize a target writer.

Tracking issue: #277  
Authenticated target plan: #305  
Full-flash validation gate: #306

## Purpose

The prior FFU boundaries authenticate one complete full-flash image, bind every destination range to one exact reviewed target, and refuse partial updates. The next independent question is whether that reviewed target still exists as a safe Linux whole-disk candidate immediately before privilege and device opening.

`PreflightAuthenticatedSingleStoreV1FullFlashTarget` re-runs the complete source, target, and full-flash validation chain and then performs current read-only target discovery. It does not trust the stale planning snapshot by itself.

## Current Linux checks

The preflight uses the repository's existing destructive-target safety policy with fixed-disk permission permanently disabled. It requires:

- the reviewed target path to resolve to exactly the same canonical `/dev/...` path;
- current `lsblk` discovery of that exact path;
- an exact match with the reviewed device identity token;
- a writable whole disk rather than a partition or other block object;
- a normal removable device or USB-attached whole disk;
- refusal of fixed/internal MMC or eMMC targets;
- refusal of the disk backing the running root filesystem;
- refusal of read-only devices;
- refusal of swap and protected system or user-data mounts;
- exact current target capacity;
- a non-zero live kernel block-device identity;
- a current kernel `major:minor` identity;
- exact logical and physical sector sizes read from sysfs; and
- continued compatibility between those sector sizes and the authenticated FFU store block size.

No `--allow-fixed` equivalent exists for the initial FFU path.

## Mount handling

The shared target policy permits only conventional removable-media mounts beneath:

- `/media`;
- `/run/media`; or
- `/mnt`.

The preflight records each eligible mounted descendant deterministically and reports `unmount_required: true`. It does not unmount anything. A later privileged transaction must guardedly unmount those exact components and then rediscover and revalidate the complete target before the first mutation.

Any mount outside those removable-media roots remains a hard refusal.

## Deterministic evidence

A successful preflight binds:

- the full-flash validation-plan digest;
- the underlying target-plan and authenticated-integrity digests;
- expected and rediscovered target identity tokens;
- exact path, capacity, logical and physical sector sizes, store block size, and mutation bytes;
- live kernel device identity and `major:minor`;
- reporting-only vendor, model, transport, removable, and hotplug fields;
- the strictly sorted eligible mount list;
- all completed safety decisions;
- the permanent absence of a fixed-disk override;
- warnings and limitations; and
- a deterministic preflight SHA-256.

The plan advances only read-only states:

- `target_discovery_completed: true`;
- `whole_disk_confirmed: true`;
- `normal_removable_target_confirmed: true`;
- `running_system_disk_excluded: true`;
- `protected_mounts_excluded: true`;
- target identity, capacity, and geometry revalidated; and
- `privileged_open_required: true`.

It retains `execution_supported: false`.

## Remaining provider boundary

This tranche deliberately performs no:

- target `open(2)` call;
- exclusive advisory or kernel writer lock;
- source hold across administrator authentication;
- guarded unmount;
- descriptor-bound capacity and identity verification;
- final revalidation immediately before mutation;
- write ordering or GPT phase execution;
- cancellation or changed-media reporting;
- flush, readback, or verification;
- Polkit command or CLI writer exposure;
- GTK integration; or
- physical boot claim.

The preflight snapshot can become stale immediately after it is produced. A future privileged provider must independently reproduce every safety fact while holding the exact source and target descriptors and must fail before mutation if any fact changes.
