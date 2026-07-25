# FFU authenticated source lease

Status: **source stability capability only**. This document does not define or authorize target access or restoration.

Tracking issue: #277  
Full-flash validation: #306  
Live target preflight: #307

## Purpose

The read-only FFU chain can authenticate one complete full-flash image and rediscover one safe removable target. Those results are snapshots. A source file could otherwise change while the user reviews the destructive operation, authenticates as an administrator, or while a later privileged process acquires the target.

`AcquireAuthenticatedFullFlashSourceLease` closes that source-side time-of-check/time-of-use gap. It accepts an already-open, read-only, identity-pinned regular FFU descriptor and requires the repository's Linux kernel read lease. The lease prevents new writable opens and truncation while held and cancels its context when a conflicting writer requests access.

## Mandatory kernel hold

The initial FFU provider has no hash-only or unsupported-filesystem fallback at this boundary.

Acquisition must:

- receive a non-nil context and already-open source descriptor;
- verify the complete originally reviewed regular-file identity;
- require a read-only descriptor;
- acquire `sourcefile.AcquireReadLease` successfully;
- reject lease conflict or lease unavailability rather than weakening the boundary;
- re-run the complete authenticated full-flash decision while using the lease-derived cancellation context;
- require exact agreement with the reviewed full-flash target preflight;
- verify the pinned source identity again after authentication; and
- confirm the kernel lease remains held before issuing the capability.

A conflicting writer request cancels the lease context and makes subsequent checks fail closed. The lease remains active until explicit cleanup, even if the parent operation is cancelled.

## Capability and evidence

The returned `FullFlashSourceLease` is sealed with an unexported capability created only after all checks succeed. Callers can:

- obtain an independently owned evidence copy;
- obtain the lease-derived context;
- recheck both the kernel lease and source identity; and
- release the lease.

Callers cannot extract a target descriptor, mutation primitive, or execution authority from the capability.

The deterministic evidence binds:

- the complete source identity and exact source size;
- live target-preflight, full-flash validation, target-plan, and authenticated-integrity SHA-256 identifiers;
- the reviewed target path, identity, and capacity;
- mandatory/held lease states;
- reproduced authentication and preflight binding states;
- the permanent refusal of fallback;
- the absence of target access and execution authority;
- warnings and limitations; and
- an outer SHA-256 plan identifier.

The caller retains ownership of the source descriptor. Closing the capability releases the kernel lease but does not close that descriptor.

## Required lifetime

A future privileged provider must keep this source capability alive through:

1. administrator authentication;
2. guarded target unmounting;
3. target opening and exclusive locking;
4. final descriptor-bound source and target revalidation;
5. every payload read and target write;
6. synchronized flush;
7. required target readback; and
8. final result publication and cleanup.

If the lease-derived context is cancelled or `Check` fails at any point, the operation must stop. Before the first target mutation the result must state that nothing was erased; after mutation it must state that the target is changed and incomplete.

## Remaining provider boundary

This tranche deliberately performs no:

- target discovery beyond comparing already-reviewed preflight evidence;
- target open or kernel identity verification;
- guarded unmount;
- exclusive target locking;
- Polkit command or administrator process launch;
- write ordering or GPT phase execution;
- target mutation;
- flush or readback;
- changed-media report generation;
- loop-device provider qualification;
- GTK integration; or
- physical boot claim.

The source lease is necessary but not sufficient for restoration. Target acquisition and the destructive transaction remain separate review gates, and execution stays disabled.
