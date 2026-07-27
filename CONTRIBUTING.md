# Contributing

The first priority is preventing writes to the wrong disk. Changes to device discovery, root-disk detection, confirmation, unmounting, partitioning, raw I/O, Polkit integration, or Windows-media creation require tests and a written explanation of the failure modes considered.

Long-running and destructive changes must also preserve upstream Rufus operation scope. State the corresponding upstream operation, complete source passes, target writes, target readback, temporary storage, scaling boundary, default versus optional verification, and every intentional Linux divergence. Ordinary creation must not become target-capacity-scaled merely because unused space is easier to model or verify. See `docs/upstream-operation-parity.md` and update `docs/operation-cost-contract.json` when work scope changes.

Run before submitting changes:

```bash
./scripts/test.sh
```

This checks Go formatting, race-enabled unit tests, `go vet`, Python GUI syntax, ARM64 compilation, Debian packaging, package inspection, and the machine-readable operation-cost contract.

Avoid adding dependencies to the privileged helper unless they provide a clear safety or maintainability benefit. The GUI must remain unprivileged and invoke destructive work only through the installed helper.
