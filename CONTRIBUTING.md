# Contributing

The first priority is preventing writes to the wrong disk. Changes to device discovery, root-disk detection, confirmation, unmounting, partitioning, raw I/O, Polkit integration, or Windows-media creation require tests and a written explanation of the failure modes considered.

Long-running and destructive changes must also preserve upstream Rufus operation scope. State the corresponding upstream operation, complete source passes, target writes, target readback, temporary storage, scaling boundary, default versus optional verification, and every intentional Linux divergence. Ordinary creation must not become target-capacity-scaled merely because unused space is easier to model or verify. See `docs/upstream-operation-parity.md` and update `docs/operation-cost-contract.json` when work scope changes.

Run before submitting changes:

```bash
./scripts/test.sh
```

This checks Go formatting, race-enabled unit tests, `go vet`, Python GUI syntax, ARM64 compilation, Debian packaging, package inspection, and the machine-readable operation-cost contract.

Avoid adding dependencies to the privileged helper unless they provide a clear safety or maintainability benefit. The GUI must remain unprivileged and invoke destructive work only through the installed helper.

## Development workflow

1. Create one narrowly scoped branch from current `main`.
2. Keep commits reviewable and avoid mixing generated artifacts, refactors, and behavioural changes without a clear reason.
3. Open a pull request using the repository template. Direct pushes to `main` should be reserved for emergency repository recovery.
4. Record the exact validation performed against the proposed head commit.
5. Merge only after required checks pass and the public claims match the available evidence.
6. Delete the merged feature branch. GitHub is configured to do this automatically; the pull request and commit history remain available.

Before changing a destructive or privileged path, document the exact source and target identities, the last safe cancellation point, every irreversible step, expected I/O volume, and the independent readback or structural evidence required for success.

## Reporting status accurately

Use the qualification language in `docs/PROJECT_STATUS.md`. In particular, do not describe loop-device success as physical boot qualification and do not describe a bounded ARM64 path as universal Rufus parity.
