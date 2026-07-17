# Pre-parity repository audit

Base: RufusArm64 0.10.4 (`7b10e134b83fca3c82f5dc354f844cee4ed2c557`)

This audit freezes feature growth while the complete repository is reviewed for correctness, safety, maintainability, performance, packaging quality, and behavioral assumptions inherited from upstream Rufus.

## Severity model

- **Critical**: plausible system-disk damage, privilege-boundary bypass, code execution, or silent corrupted-media success.
- **High**: incorrect destructive behavior, broken identity/cancellation guarantees, unsafe parser bounds, or a supported workflow that commonly fails.
- **Medium**: false acceptance/refusal, stale GUI state, incomplete cleanup, misleading diagnostics, portability defects, or significant inefficiency.
- **Low**: maintainability, spelling, documentation drift, weak tests, or minor UX inconsistency.

Each accepted finding must record evidence, affected paths, a regression test, the fix, and x86-64/native-ARM64 CI status.

## Review matrix

- [ ] Repository inventory and architecture map
- [ ] Privileged helper command surface and Polkit boundary
- [ ] Whole-device selection, identity binding, mounts, swap, and system-disk refusal
- [ ] Raw image writing, flushing, reread, and verification
- [ ] Container decompression and virtual-disk conversion limits
- [ ] MBR/GPT parsing and arithmetic overflow/underflow
- [ ] ISO9660, El Torito, PE/COFF, Authenticode, DBX, and SBAT parsing
- [ ] Windows FAT32/NTFS media creation, WIM splitting, UEFI:NTFS, and BIOS assets
- [ ] Driver staging and generated Windows Setup configuration
- [ ] Linux persistence detection, layout, manifest, copy, patch, filesystem, and qualification
- [ ] Symlink, path, case-folding, temporary-file, descriptor, and mount safety
- [ ] Cancellation, process groups, timeouts, goroutines, threads, and cleanup
- [ ] GTK state transitions, stale selections, semantics, accessibility, and diagnostics
- [ ] Acquisition trust metadata, rollback state, downloads, and cache behavior
- [ ] Debian packaging, desktop integration, dependencies, upgrades, and reproducibility
- [ ] CI, race/static/security checks, fuzzing, negative tests, and coverage blind spots
- [ ] Documentation, version strings, unsupported claims, spelling, and stale terminology
- [ ] Behavioral comparison against the pinned upstream Rufus source

## Confirmed findings

### A-001 — Omitted root alias can reserve a FAT32 destination name

**Severity:** Medium

`internal/linuxmedia/manifest.go` adds the logical path to the case-insensitive FAT32 collision map before resolving a symbolic link. A direct root-self alias such as `ubuntu -> .` is subsequently omitted because it cannot be represented safely, but its folded pathname remains reserved. A later real destination path differing only by case can therefore be rejected even though the omitted alias would never exist on the output filesystem.

**Required correction:** register a path in the FAT32 destination namespace only when an entry will actually be materialized. Preserve collision checks for ordinary files, directories, and safely dereferenced links. Add a regression test containing an omitted root alias and a real case-related path.

**Status:** confirmed; fix and regression test pending surrounding manifest/copy audit.

## Tooling gaps identified

The current suite already runs Go formatting, race tests, shuffled tests, vet, coverage, Python byte-compilation/unit tests, package extraction checks, architecture checks, and pinned-asset hashes. Additional audit gates to evaluate include:

- ShellCheck rather than syntax-only shell validation
- Python linting and static typing
- `staticcheck` and `govulncheck`
- fuzz targets for binary and filesystem parsers
- deterministic/reproducible package comparison
- explicit timeout/leak tests for cancellation and subprocess cleanup
- property tests for partition arithmetic and size conversion
- package upgrade/downgrade and stale-desktop-cache integration tests

No new parity feature should be merged until critical/high findings are closed and the remaining medium/low findings are documented with disposition.