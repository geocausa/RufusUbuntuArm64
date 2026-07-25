# Graphical FFU restore contract

This document defines the pure graphical contract between a completed read-only FFU review and the existing privileged experimental restore provider.

## Command construction

The graphical layer may construct a privileged restore command only from one successfully normalized review. The reviewed target must already be fully unmounted. RufusArm64 performs no automatic or guarded unmount in this boundary.

The command binds:

- the exact canonical source path;
- exact target path, identity, capacity and logical/physical sector geometry;
- the same authenticated trust-store root and explicit policy-file paths;
- the byte-exact destructive confirmation phrase; and
- the stable reviewed-input SHA-256 emitted by the read-only review.

The only privilege transition is the package-owned helper launched through the configured `pkexec` path. Fixed-disk override, automatic unmount, implicit confirmation and ordinary raw-writer flags are forbidden.

## Result correlation

The result normalizer validates the entire returned evidence chain:

1. the privileged process reproduced the same stable review;
2. the mandatory source lease binds the reproduced target preflight;
3. the exclusive target session binds that source lease and the same kernel target identity;
4. the exact confirmation binds the same target, capacity and mutation scope;
5. the one-shot mutation authorization binds the same single-phase write order; and
6. execution binds all prior evidence identifiers and reports exact operation and byte accounting.

The normalizer rejects source, policy, trust-generation, target, kernel-identity, plan, phrase, geometry, mutation-scope or evidence substitution.

## Outcome classes

A successful result is accepted only when the executor reports `verified` after complete writing, synchronization, readback and final revalidation.

A failed result is separated into three user-visible states:

- `not-started`: no target bytes were written;
- `partially-modified`: writing began but the transaction did not finish; and
- `written-unverified`: all planned bytes were written and synchronized, but complete readback verification did not finish.

The latter two states always instruct the operator not to boot or reuse the target and to perform a fresh full restoration. Cancellation after mutation begins is never displayed as a safe cancellation.

## Deliberate exclusions

This tranche does not add the destructive GTK button, administrator prompt, subprocess lifecycle, cancellation UI, automatic unmount or hardware boot claim. Those remain separate reviewable gates.
