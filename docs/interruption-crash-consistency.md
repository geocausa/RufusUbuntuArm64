# Interruption and crash-consistency qualification

RufusArm64 treats interruption behavior as a release property, not as an informal collection of tests. The machine-readable inventory is [`interruption-qualification.json`](interruption-qualification.json), and `go test ./internal/qualification -run TestInterruptionQualificationMatrix` checks that the inventory remains structurally complete and points to real executable regressions.

## What the matrix proves

Each automated row names one exact Go test and one invariant. The checker requires the test source and function to exist, rejects duplicate identifiers and undeclared boundaries, and requires every admitted boundary to be represented either by an automated/physical row or by an explicit residual software gap.

The initial inventory records existing coverage for:

- no-replace metadata preflight and rollback of partially published record/evidence pairs;
- complete rollback of runtime-integrity installation and removal at every admitted transaction boundary;
- FFU cancellation before and after mutation, partial writes, synchronization failure, and readback mismatch;
- acquisition metadata rollback refusal and symbolic-link destination substitution.

The inventory deliberately keeps uncovered software cases visible. A missing drive-backup publication, partition/filesystem mutation, persistence materialization, acquisition-cache transaction, or helper-process cleanup case may not disappear from review merely because another component has a similar test.

## Required result semantics

Pre-mutation failure or cancellation must leave the target and external destinations unchanged. Post-mutation failure must never report success and must retain conservative evidence that media may be incomplete or modified. Publication must not replace an existing regular file, symbolic link, or substituted path. Cleanup may remove only objects demonstrably owned by the current operation; ambiguous state must be retained or refused under a documented recovery contract.

Tests may add package-private hooks, injected readers/writers, synchronization functions, process fixtures, or test-build-only seams. Production CLI and GTK interfaces must never expose a fault-injection switch.

## Physical-only boundary

Unit tests, loop devices, virtual machines, and process termination cannot prove behavior under electrical power removal. The matrix therefore records real power loss and subsequent firmware boot as `physical-only` rows. Those rows require a hardware qualification record containing the host, firmware, controller/media identities, interruption point, observed recovery state, independent verification, and boot result. Software qualification must not convert those rows to “passed” by simulation.

## Updating the inventory

When a software gap gains executable coverage:

1. add the regression in the owning package;
2. replace the corresponding `residual_software_gaps` row with one or more exact `entries` rows;
3. keep the boundary identifier stable unless the safety model itself changed;
4. run the full exact-head CI and qualification matrix on x86-64 and native ARM64.

New destructive or durable workflows must add their boundaries before merge. The checker is intentionally fail-closed: a boundary cannot be omitted merely because its test has not been written yet.
