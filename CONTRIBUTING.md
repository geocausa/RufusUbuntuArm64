# Contributing

The first priority is preventing writes to the wrong disk. Changes to device discovery, root-disk detection, confirmation, unmounting, partitioning, raw I/O, Polkit integration, or Windows-media creation require tests and a written explanation of the failure modes considered.

Run before submitting changes:

```bash
./scripts/test.sh
```

This checks Go formatting, race-enabled unit tests, `go vet`, Python GUI syntax, ARM64 compilation, Debian packaging, and package inspection.

Avoid adding dependencies to the privileged helper unless they provide a clear safety or maintainability benefit. The GUI must remain unprivileged and invoke destructive work only through the installed helper.
