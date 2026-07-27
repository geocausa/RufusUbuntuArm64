# FFU sealed mutation authorization

The exact destructive phrase and a deterministic write-order plan are necessary
but not individually sufficient to authorize mutation. Stage 3 therefore adds a
sealed package capability that correlates both while every live source and target
safety boundary is still healthy.

## Authorization inputs

`AuthorizeSinglePhaseFullFlashMutation` requires:

- the live `FullFlashDestructiveConfirmation` capability;
- the unchanged single-store-v1 descriptor plan;
- the exact restore-target plan; and
- the resolved full-flash validation plan.

The function checks the confirmation capability, obtains its sealed evidence,
and internally calls `PlanSinglePhaseFullFlashWriteOrder`. A caller cannot supply
or substitute a precomputed write-order plan. The confirmation is checked again
after planning, and every confirmation evidence field relevant to source,
target, capacity, mutation scope, and phrase must remain unchanged.

## Exact correlation

Authorization requires agreement among:

- confirmation, target-session, source-lease, and live-preflight SHA-256 evidence;
- descriptor, target, full-flash validation, authenticated-integrity, catalog,
  hash-table, and write-order plan identifiers;
- canonical device path and target identity;
- target capacity and store block size;
- operation count and total mutation bytes; and
- the exact target-and-capacity destructive phrase.

Staged-GPT profiles remain ineligible because the prerequisite write-order
planner refuses them. Missing, substituted, re-digested, closed, or changed
capabilities and plans fail closed.

## Sealed capability

A successful result sets `mutation_permitted` only inside an unexported-seal
`FullFlashMutationAuthorization`. Callers may obtain deterministic evidence and
check continued health, but cannot extract:

- the source file;
- the target descriptor;
- the internally reproduced operation list; or
- any read, write, seek, sync, ioctl, unmount, or privilege method.

The authorization is initially unconsumed and explicitly requires a later
one-shot execution transaction. `execution_supported` remains false and no target
byte is modified by this boundary.

## Remaining destructive transaction

A future executor must live in the FFU package and must:

1. accept the sealed authorization capability rather than loose evidence;
2. recheck the authorization, confirmation, source lease, and target session
   immediately before the first mutation;
3. atomically consume the authorization before the first write;
4. execute only the internally held declaration-order operations;
5. distinguish cancellation before mutation from cancellation or failure after
   mutation begins;
6. synchronize the target and read back every written extent; and
7. report when the target may be partially modified.

Provider integration, administrator authentication, GTK exposure, real signed
FFU evidence, disposable-device qualification, and physical boot testing remain
separate gates.

## Qualification scope

Synthetic integration tests construct a signed single-phase FFU, acquire a real
kernel source lease, hold an injected exclusive regular-file target, consume the
exact destructive phrase, and then authorize mutation while proving the target
bytes remain unchanged. Tests also cover deterministic evidence, staged-profile
refusal, target substitution, closed-target invalidation, nil and cancelled
contexts, and evidence tampering.

Focused race analysis, pinned Staticcheck, Linux ARM64 compilation, complete CI,
and both privileged loop-device qualification suites remain mandatory before
merge.
