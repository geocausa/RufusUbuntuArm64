# Graphical FFU restore dialog

The GTK FFU dialog now joins the authenticated read-only review to the existing privileged single-process restore provider while preserving the Stage 3 destructive boundaries.

## One review, one attempt

A restore button becomes available only after a successful review of an already-unmounted removable whole disk. The operator must type the exact displayed target-and-capacity phrase. The command carries the stable reviewed-input SHA-256, so the privileged process refuses source, policy, trust-generation, target, capacity, geometry or kernel-identity substitution.

Each review permits at most one restore launch. A cancelled administrator prompt, provider failure or completed transaction invalidates the review and requires a new authentication and review before another attempt.

## Privilege and target policy

The dialog launches only the package helper through the configured `pkexec` path. It does not perform or request automatic unmount, fixed-disk override, implicit confirmation or ordinary raw writing. The privileged helper reruns the complete authentication and live target policy before acquiring the target.

## Process ownership and cancellation

The restore runs outside the GTK thread in its own process group. The dialog cannot close while review or restoration is active. Cancel sends `SIGTERM` to the provider process group; the existing signal-aware CLI carries cancellation through source leasing, target acquisition, writing, synchronization and readback.

Cancellation is not considered safe until final structured evidence is returned. Cancellation after mutation begins remains a partially modified target state.

## Final evidence handling

When structured output is available, the GUI validates the complete review, source lease, target session, confirmation, mutation authorization and executor chain before displaying an outcome.

- verified results report successful synchronization and complete readback;
- not-started results report that no target bytes were written;
- partial or written-unverified results display an explicit do-not-boot warning; and
- missing, malformed or uncorrelated final evidence is treated as an unknown, possibly modified target state.

The GUI never infers a safe target merely from a process exit code or a cancelled prompt.

## Remaining qualification

This is still an experimental provider. A real signed vendor FFU must be exercised on disposable physical removable hardware and firmware-boot qualified before a production support claim or automatic workflow is appropriate.
