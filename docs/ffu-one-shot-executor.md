# FFU one-shot single-phase execution transaction

This boundary is the first Stage 3 FFU component permitted to modify the held
target. It accepts only the unexported-seal mutation authorization and never
reopens either the source or target path.

## Lock and capability order

The executor holds capabilities in one fixed order for the complete transaction:

1. mutation authorization;
2. exact destructive confirmation;
3. exclusive target session; and
4. authenticated source lease.

While those locks are held, close and reuse attempts cannot race the transaction.
The executor validates every seal and evidence digest, rechecks the kernel source
lease and complete source identity, verifies the already-open target descriptor,
rediscoveries target policy and geometry, confirms the target is still unmounted,
and proves the source remains outside the target.

## One-shot consumption

Cancellation before the final live checks leaves the authorization reusable and
reports `not-started`. After all checks pass, the authorization is marked consumed
immediately before the first possible target write. A consumed capability cannot
be checked or executed again.

No source path, target path, or caller-supplied operation list is accepted. The
executor uses only the package-private source file, target descriptor, and
single-phase declaration-order operations retained by the authorization.

## Write transaction

For every ordered operation, the executor:

- reads a bounded chunk from the exact authenticated FFU payload offset;
- writes the chunk to the exact resolved target offset;
- tracks completed operations and mutation bytes; and
- checks context cancellation and the source lease between chunks.

Payload reused by multiple FFU locations is read and written independently for
each declared location. Short reads, short writes, source lease breaks, identity
changes, target changes, cancellation, and I/O failures stop the transaction.

## Durability and readback

After every operation is written, the target descriptor is synchronized with
`fsync`. The source and target are then revalidated. Every written extent is read
back from the same held target descriptor and compared byte-for-byte with the
same held authenticated source descriptor. A final live revalidation is required
before success.

Success is reported only when:

- all operations and bytes were written;
- target synchronization completed;
- every written extent matched readback; and
- the source lease, source identity, target descriptor, target policy, mount
  state, capacity, and geometry remained valid.

## Explicit failure states

Every attempted execution returns structured evidence even when it returns an
error:

- `not-started`: no target byte was written;
- `partially-modified`: mutation began but the write or durability transaction
  did not complete safely;
- `written-unverified`: all planned bytes were written and synchronized, but
  readback or final verification did not complete; or
- `verified`: the complete transaction succeeded.

Cancellation is separately classified as before or after mutation. Any failure
once mutation begins sets `target_may_be_partially_modified`, preventing a caller
from treating an error as an unchanged device.

## Remaining integration boundary

The executor performs no device-path open, unmount, administrator authentication,
Polkit request, subprocess execution, or GTK operation. It is not yet connected
to a provider or user interface. Real loop-device execution qualification,
provider result publication, administrator-authentication flow, real signed FFU
evidence, disposable-device testing, and physical boot validation remain
separate gates.
