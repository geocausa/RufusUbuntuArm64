# FFU software audit and release disposition

Date: 2026-07-26  
Audited Stage 3 parent: `8761b3b448800627e3001b5b91ec47f8e6e1de45`

## Disposition

The software implementation for the current experimental FFU profile is complete enough to move forward without waiting for unavailable physical qualification hardware.

This disposition applies only to the authenticated **single-store-v1, full-flash, non-staged** profile already accepted by the parser and planner. The feature remains explicitly experimental and opt-in. This document does not claim that a restored device has booted, does not convert software verification into firmware validation, and does not create a general production-support promise.

Physical restoration and firmware boot qualification are deferred to a separate evidence gate. Defects discovered during later real-device use remain normal maintenance work and must not be hidden or reclassified as already qualified.

## Audited chain

The review covered the complete implemented boundary:

1. bounded FFU parsing, descriptor resolution and authenticated catalog/hash-table/source-chunk verification;
2. explicit trust-metadata and publisher policies plus durable trust-generation activation;
3. stable reviewed-input binding across source, policies, trust generation and exact target geometry;
4. fresh removable whole-disk discovery, root-disk exclusion and mounted-target refusal;
5. mandatory source lease and exclusive `O_RDWR | O_EXCL | O_NOFOLLOW` target acquisition;
6. byte-exact destructive confirmation and one-shot mutation authorization;
7. declaration-order writes, synchronization, complete written-extent readback and final live revalidation;
8. explicit `not-started`, `partially-modified`, `written-unverified` and `verified` results;
9. signal-aware CLI cancellation and guarded GTK process-group cancellation;
10. complete graphical evidence correlation and fail-closed unknown-target handling; and
11. deterministic physical-qualification records that cannot manufacture a boot claim.

The existing main CI, native ARM64 execution, reproducible packaging, static/vulnerability checks, FreeDOS and non-bootable loop suites, and privileged FFU loop transaction remain required. The permanent `FFU software release audit` workflow adds one focused gate over the complete provider, safety, graphical and evidence boundary.

## Release decision

Stage 3 may treat safe FFU restoration as a **software-complete experimental feature** when the focused audit and the repository's existing exact-head gates pass.

The shipped wording must continue to state all of the following:

- use only disposable removable media whose complete contents may be destroyed;
- the exact supported FFU profile is narrow and authenticated;
- automatic unmounting and fixed/internal-disk overrides are unavailable;
- staged-GPT, partial-update, validation-descriptor and unknown profiles are refused;
- cancellation after mutation can leave the target unusable;
- success means synchronized writes plus complete readback of every planned extent;
- software verification does not prove firmware bootability or physical-device health; and
- physical qualification is pending and does not block experimental availability.

Issue closure for the software milestone must therefore mean **implementation and software qualification complete**, not **hardware boot qualification complete**.

## Non-blocking hardening backlog

The audit found no software defect that justifies keeping the implemented experimental milestone open after all exact-head gates pass. The following improvements remain worthwhile but are not required to expose the already guarded experimental path:

- reject duplicate JSON member names in caller-provided policy documents and graphical evidence input, rather than relying on one parser's last-member behaviour;
- place explicit size limits on captured GTK helper stdout and stderr, in addition to the provider's bounded structured evidence;
- use exact JSON-number decoding for `lsblk` byte values, avoiding the current generic numeric conversion even though realistic removable-media capacities remain far below the precision boundary; and
- replace utility-name lookup with explicit trusted utility resolution where practical. The privileged GTK path is launched through `pkexec`, which supplies a minimal safe environment, but direct resolution would make the dependency boundary more obvious.

These items should be tracked and fixed through ordinary hardening pull requests. None may be used to weaken target policy, confirmation, authentication, synchronization, readback or evidence requirements.

## Deferred physical gate

When suitable hardware becomes available, qualification still requires one genuine signed vendor FFU, disposable physical removable media, a verified restore result, the same-media assertion, an intended ARM64 firmware boot attempt, and SHA-256-addressed supporting evidence. A failed physical test should reopen only the affected implementation or compatibility boundary; it does not retroactively invalidate the software-audit record.
