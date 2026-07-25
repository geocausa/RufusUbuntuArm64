# FFU exact destructive confirmation

Status: **exact phrase verification without mutation authority**. This document does not authorize or execute restoration.

Tracking issue: #277  
Authenticated source lease: #308  
Exclusive target acquisition: #309

## Purpose

The authenticated FFU source can now be held stable under a mandatory Linux read lease, and one already-unmounted removable target can be held through a sealed kernel-exclusive session. Neither capability permits mutation.

The next independent safety boundary is proving that the user supplied the exact reviewed destructive phrase while both capabilities are still healthy.

`ConfirmExclusiveFullFlashTarget` performs that check and returns a separate sealed confirmation capability. It does not expose either descriptor and does not add a writer.

## Exact phrase

The only accepted phrase is:

```text
RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES
```

`/dev/DEVICE` is the exact canonical path bound by the target plan and exclusive session. `N` is the exact reviewed target capacity rendered as canonical base-10 digits.

The comparison is byte-for-byte. The boundary refuses:

- empty input;
- leading or trailing whitespace;
- a trailing newline;
- case changes;
- a different path;
- a different capacity;
- decimal padding such as a leading zero;
- additional words or punctuation; and
- overlong input.

The supplied phrase is compared with constant-time byte comparison after an exact length check. The raw caller input is not retained; deterministic evidence records the expected canonical phrase and its SHA-256.

## Capability checks

Before comparing the phrase, the boundary requires the exclusive target session to pass its full health check. That transitively proves:

- the mandatory source lease remains held;
- the complete source identity remains unchanged;
- the target descriptor remains open and kernel-exclusive;
- target identity and capacity still match;
- the whole-disk removable-target policy still passes;
- the target remains unmounted;
- sector geometry remains unchanged; and
- the source remains outside the selected target.

After an exact phrase match, the complete target session is checked again. The before/after evidence must agree exactly on its plan digest, source-lease binding, path, target identity, capacity, and mutation-byte scope.

Any capability change, cancellation, close, lease break, target substitution, remount, geometry change, or source mutation prevents confirmation.

## Sealed confirmation capability

`FullFlashDestructiveConfirmation` has an unexported seal and retains the exact target session only so later health checks can prove that the confirmation still refers to the same live capabilities.

It exposes only:

- independently owned deterministic evidence; and
- an explicit health check.

It exposes no source descriptor, target descriptor, read method, write method, positional I/O, seek, sync, ioctl, unmount, privilege, or execution method.

Closing or invalidating the underlying source lease or target session invalidates the confirmation capability.

## Deterministic evidence

A successful confirmation binds:

- target-session and source-lease evidence SHA-256 identifiers;
- live target-preflight, full-flash validation, restore-plan, and authenticated-integrity SHA-256 identifiers;
- exact target path, target identity, capacity, and mutation-byte scope;
- the expected canonical confirmation phrase and its SHA-256;
- exact-match and consumed states;
- healthy source-lease and target-session states;
- acquired target-access state;
- explicit non-performance of guarded unmounting;
- warnings and limitations; and
- an outer deterministic plan SHA-256.

It advances:

- `confirmation_exact_match: true`;
- `confirmation_consumed: true`.

It retains:

- `guarded_unmount_performed: false`;
- `mutation_permitted: false`;
- `execution_supported: false`.

## Remaining execution boundary

This tranche deliberately performs no:

- guarded target unmount;
- Polkit or administrator command exposure;
- write-order or GPT-phase planning;
- mutation authorization;
- source-to-target copying;
- cancellation or changed-media report transition;
- synchronized flush;
- target readback or verification;
- loop-device restore execution;
- GTK integration; or
- physical boot claim.

The exact phrase is necessary but insufficient for restoration. A later execution design must still establish evidence-backed write ordering, interruption semantics, verification scope, and result-state rules before any byte can be modified.
