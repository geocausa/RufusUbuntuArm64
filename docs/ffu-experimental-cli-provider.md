# Experimental single-process FFU CLI provider

Stage 3 exposes the authenticated single-phase FFU pipeline through the existing
`rufusarm64-cli` binary without weakening any package safety boundary. The
provider is deliberately command-line only and requires an explicit experimental
acknowledgement.

## Commands

`ffu review` performs a non-mutating review. It requires:

- the selected FFU image path;
- the exact removable whole-disk path and reviewed identity token;
- the reviewed target capacity and logical/physical sector sizes;
- the durable authenticated FFU trust-store root;
- the caller-provisioned trust-metadata public-key policy; and
- the explicit catalog publisher policy.

The review activates only the durable authenticated trust generation, opens an
identity-pinned regular FFU source, reauthenticates the complete single-store-v1
pipeline, rediscovers the target, and prints or emits JSON containing the exact
target-and-capacity confirmation phrase. It never opens the target.

`ffu restore` requires the same inputs, the exact phrase returned by review,
administrator privileges, and `--experimental-ffu`. It reruns the entire review
inside the privileged process rather than trusting serialized plans from the
unprivileged invocation.

## Single-process capability chain

The restore command keeps every destructive capability in one process:

1. activate the exact durably authenticated trust-store generation;
2. open and identity-pin the FFU source;
3. resolve authenticated integrity, publisher policy, target plan, and full-flash
   profile;
4. rediscover the selected target and require exact identity, capacity, geometry,
   removable-media policy, system-disk exclusion, and mount state;
5. acquire the mandatory Linux source read lease;
6. open and hold the exact target under kernel exclusivity;
7. consume the exact destructive phrase;
8. issue the sealed mutation authorization; and
9. execute the one-shot write, synchronization, and readback transaction.

The command does not pass descriptors or trust decisions through environment
variables, standard input, temporary files, or another process. It performs no
nested `pkexec`, Polkit, subprocess, or guarded-unmount action.

## Policy files

Both JSON policy files are selected as identity-pinned regular files, bounded to
1 MiB, decoded with unknown fields forbidden, and rejected when empty or when
multiple JSON values are present. The trust and publisher packages perform their
full canonicality, validity-window, key, root, and publisher-pin validation.

There is no built-in Microsoft, OEM, test, host-TLS, or accept-all trust policy.
A restore cannot proceed until an operator has independently published a valid
trust-store generation and supplied matching explicit policies.

## Signal cancellation

Both review and restore install one signal-aware context for `SIGINT` and
`SIGTERM`. Cancellation is checked before policy or image inputs are opened and
is carried through authentication, source leasing, target acquisition,
confirmation, authorization, writing, synchronization, and readback.

A signal observed before the first target write returns without modifying the
target. A signal observed after mutation begins returns the executor's structured
partial-modification evidence; the command never reports an interrupted target as
verified.

## Output and failure state

JSON mode emits the review evidence, source lease, target session, destructive
confirmation, mutation authorization, and final execution result. When execution
returns an error after mutation begins, the structured result still identifies
whether the target is partially modified or written but unverified.

The target must already be completely unmounted. Fixed-disk overrides, automatic
unmount, staged-GPT profiles, alternate write ordering, and confirmation bypasses
are not accepted.

## Remaining UI boundary

This command is an experimental provider surface, not a general user-facing FFU
workflow. GTK review, safe administrator-authentication handoff, cancellation UI,
result presentation, real signed Microsoft/OEM FFU evidence, disposable physical
media qualification, and firmware boot validation remain separate gates.
