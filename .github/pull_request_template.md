## Summary

Describe the change and the user-visible or engineering problem it addresses.

## Safety impact

- Destructive-device path affected: yes / no
- Privilege boundary affected: yes / no
- Source/target identity contract affected: yes / no
- Failure modes considered:

## Upstream/parity impact

Identify the corresponding Rufus behaviour or state why this is an intentional Linux-specific divergence. Update the parity and operation-cost contracts when scope changes.

## Validation

List the exact commands, test fixtures, loop-device runs, architecture checks, package checks, and physical hardware evidence completed for this commit.

## Checklist

- [ ] The change is narrowly scoped and documented.
- [ ] Destructive operations fail closed on ambiguous identity, capacity, geometry, or source evidence.
- [ ] Tests cover success, cancellation, mutation, and relevant failure paths.
- [ ] `./scripts/test.sh` passes, or any omitted gate is explained.
- [ ] Public claims distinguish software verification from physical boot qualification.
- [ ] No private key, credential, personal data, or unreviewed binary asset is included.
