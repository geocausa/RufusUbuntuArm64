# Pre-0.11 full-code audit

Date: 2026-07-17

Baseline: `7b10e134b83fca3c82f5dc354f844cee4ed2c557` (`0.10.4`)

This document is the release gate for resuming Rufus-parity work. It reviews the Linux-native implementation from destructive-operation safety, privilege separation, source and target identity, parser robustness, integer arithmetic, external-command execution, concurrency and cancellation, performance, packaging, CI, documentation, and upstream-Rufus parity perspectives.

Statuses:

- **confirmed** — demonstrated directly from the current call chain or by a focused regression case;
- **fixing** — accepted for the audit branch and requires code plus tests;
- **deferred** — valid hardening work that is too broad to mix into a small corrective commit;
- **cleared** — investigated and not a defect;
- **planned** — parity work, not a regression in the released contract.

## Release blockers

### A-001 — target identity is relaxed after confirmation

**Severity:** critical safety hardening  
**Status:** fixing

The ordinary writer and dedicated persistence helper validate the GUI-provided target identity initially, but later callbacks call `RevalidateTarget` with an empty expected identity. The identity token intentionally excludes the child partition layout, so it remains valid across wiping, partitioning, and formatting. Dropping it weakens protection against disconnect/reconnect or `/dev/sdX` reuse during a long preparation or creation operation.

Required correction:

- retain the selected identity through every pre-destructive and post-layout revalidation;
- keep open-descriptor `dev_t` and capacity checks as an independent second boundary;
- add tests proving partition-layout changes do not alter a whole-disk token, while disk sequence and device identity changes do.

### A-002 — unchecked capacity arithmetic in untrusted-media planning

**Severity:** high  
**Status:** fixing

Several image and Windows-media calculations use unchecked `uint64` addition or alignment arithmetic. The practical values of ordinary images are small, but parsers and sparse files are attacker-controlled. Overflow can produce a falsely small required capacity, incorrect progress totals, or an invalid offset.

Affected classes include:

- decompressed-byte counters and size-limit writers;
- Windows ISO, split-WIM, answer-file, and driver-folder totals;
- GPT alignment and partition-end calculations;
- Linux-media aligned byte/sector conversions;
- image-sector rounding near the signed file-size limit.

Required correction:

- centralize checked add, multiply, subtract, and align-up helpers;
- fail before target erasure on overflow;
- add boundary and malicious-size regression tests.

### A-003 — privileged executable and asset overrides are environment-selected

**Severity:** high defense in depth  
**Status:** fixing

The Windows-media engine accepts `RUFUSARM64_WIMLIB` before package-owned candidates, and the graphical launchers accept helper-path environment overrides. Normal `pkexec` deployments commonly sanitize the environment, and a root caller can already execute arbitrary programs, but privileged code should not depend on that assumption.

Required correction:

- production GUI launchers use package-owned helper paths;
- the privileged WIM resolver uses the executable-adjacent package asset, the pinned package path, then a trusted system `PATH` fallback;
- test injection uses explicit package-level hooks or test-only controls rather than production environment overrides;
- keep the UEFI:NTFS checksum pin even for development candidates.

### A-004 — Windows media traversal is not bounded by entry count

**Severity:** high availability and preflight robustness  
**Status:** fixing

Persistence media inspection has explicit entry and byte ceilings. Windows ISO and driver-folder walks reject special files and links but have no entry-count ceiling, and some byte totals are unchecked. A pathological image can consume excessive time and memory before the destructive boundary.

Required correction:

- cap Windows ISO and driver-folder entries with conservative documented limits;
- use checked totals tied to the selected target capacity;
- preserve support for normal Microsoft media and large driver sets;
- add over-limit and overflow tests.

### A-005 — no-replace acquisition can overwrite a file created during download

**Severity:** medium correctness  
**Status:** fixing

When replacement is disabled, the destination is checked before transfer, but the final same-directory `rename` can replace a file created after that check. This violates the command's no-replace contract.

Required correction:

- use an atomic no-replace installation primitive on Linux;
- keep temporary data in the destination directory;
- sync the file and parent directory;
- add a race-contract regression test.

## Privilege and destructive-operation hardening

### A-006 — Polkit policy permits inactive and nonlocal authentication

**Severity:** medium  
**Status:** fixing

The package-owned helpers are intended for active graphical sessions. `allow_any` and `allow_inactive` currently request administrator authentication rather than denying those contexts.

Required correction:

- set inactive and arbitrary-session defaults to `no`;
- retain fresh `auth_admin` for the active session;
- keep the separate persistence action and helper boundary.

### A-007 — path-based destructive utilities remain after descriptor pinning

**Severity:** medium  
**Status:** deferred

The core writers hold and verify a whole-disk descriptor, but some Windows-media operations still invoke `wipefs`, `blockdev`, formatting, checking, or partition-node operations by pathname. Partition geometry and parent-device checks substantially reduce risk, but descriptor-based invocation should be used wherever the external tool accepts `/proc/self/fd/N`, following the stronger persistence implementation.

Follow-up work:

- pass the whole disk and partitions as inherited descriptors when supported;
- keep descriptors open through formatting, checking, final flush, and partition reread;
- add hot-unplug and path-reuse integration tests.

### A-008 — Windows GPT metadata lacks the persistence path's exact readback check

**Severity:** medium  
**Status:** deferred

The Windows creator writes primary/backup GPT structures and later validates partition-node geometry. The persistence creator additionally reads back and verifies the exact GPT metadata. Bring the Windows path to the same standard before declaring storage-layout parity.

### A-009 — legacy systems can expose weaker whole-disk identity

**Severity:** low to medium  
**Status:** deferred

The identity token includes `MAJ:MIN`, `diskseq`, serial, WWN, size, model, vendor, transport, and policy flags. On older kernels or inexpensive USB bridges, `diskseq`, serial, and WWN can all be absent. Add stable sysfs/USB topology identifiers where available, while retaining open-descriptor identity and capacity checks.

## GUI, semantics, and concurrency

### A-010 — packaged GUI is rewritten by string substitution

**Severity:** high maintainability and test fidelity  
**Status:** fixing

`build-deb.sh` mutates persistence labels and explanatory text after copying the tested Python source. The installed application therefore differs from the source exercised by normal Python tests, and harmless wording refactors can break packaging.

Required correction:

- put the shipped wording and controls directly in `gui/rufusarm64.py`;
- remove package-time semantic replacements;
- restrict package stamping to the version constant;
- test the source and installed GUI for the same persistence boundary.

### A-011 — one visible icon still hides the real creator too deeply

**Severity:** medium usability  
**Status:** fixing

Desktop actions are not obvious in every GNOME application-grid interaction. Add a direct **Open Persistent USB Creator** control inside the single visible RufusArm64 window. It must launch the guarded wizard and must not silently change the ordinary **Create USB** button's mode.

### A-012 — image inspection and device refresh can block the GTK thread

**Severity:** medium performance and responsiveness  
**Status:** deferred

Image inspection has a 20-second subprocess timeout and device enumeration a 15-second timeout, both invoked synchronously from GTK callbacks. Slow storage, `lsblk`, or compressed previews can freeze the window.

Follow-up work:

- execute inspection and enumeration in worker threads;
- tag requests with monotonically increasing generations so stale results cannot replace a newer selection;
- display cancellable progress and preserve the current safety identities.

### A-013 — DBX update is asynchronous but not part of the GUI busy state

**Severity:** medium concurrency  
**Status:** fixing

A DBX download can run while a write is started. The completion callback may change the selected DBX path during another operation. Give DBX acquisition its own task token or include it in the shared busy state, and ignore stale completions.

### A-014 — settings-file update is not fully durable or symlink-averse

**Severity:** low  
**Status:** fixing

The GUI uses a predictable `.tmp` path and atomic replace but does not create a unique no-follow temporary file or sync the containing directory. The directory is normally private, so impact is limited to the same user.

Required correction:

- create a unique temporary file in the private config directory;
- set mode before exposing content;
- flush the file and parent directory;
- replace atomically and reject an unsafe config directory.

## Windows customization semantics

### A-015 — local-account password sentinel was initially misread; behavior matches upstream

**Severity:** none  
**Status:** cleared

`UABhAHMAcwB3AG8AcgBkAA==` with `PlainText=false` is Microsoft's unattend representation for an empty password, not a universal login password. Upstream Rufus uses the same value and follows it with `net user ... /logonpasswordchg:yes`.

Required maintenance:

- document the counterintuitive encoding next to the generator;
- add a regression test that establishes the intended empty-password semantics and prevents replacement with a real fixed credential.

### A-016 — Windows options trail upstream Rufus 4.15

**Severity:** parity gap  
**Status:** planned

Missing or incomplete items include current QoL/application-removal options, SkuSiPolicy handling, newer OOBE behavior, silent-install safeguards, and Windows To Go. These must not be added until the audit blockers are closed and each behavior has Microsoft-version and architecture tests.

## Parser and validation review

### A-017 — image sector rounding can overflow signed file size

**Severity:** medium  
**Status:** fixing

`(size + 511) / 512` can overflow near `MaxInt64` for a sparse file. Use division plus remainder without signed addition.

### A-018 — 0.11 UEFI scanner bounds only EFI-file count

**Severity:** medium  
**Status:** fixing before rebase

The pending UEFI validator limits discovered `.efi` files but can walk an unbounded number of unrelated paths. Add a total-entry ceiling, reject duplicate `.sbat` sections, validate all relevant PE section extents, and reduce parser duplication with the existing Authenticode code where practical.

### A-019 — DBX update authenticity is structural plus HTTPS, not signer verification

**Severity:** medium trust semantics  
**Status:** deferred/documentation

The DBX updater downloads from Microsoft's official repository and parses the authenticated-update container, but it does not cryptographically verify the PKCS#7 signer. It never modifies firmware and is used only to refuse media, so the main consequence is a false refusal rather than firmware compromise.

Required correction before stronger claims:

- document the exact trust boundary;
- verify the signed-variable update against an explicit Microsoft trust anchor;
- keep hash/certificate revocation checks separate from firmware-state claims.

### A-020 — persistence detector and patcher are intentionally narrow

**Severity:** none  
**Status:** cleared

The fixed configuration-path list, bounded reads, exact kernel-command recognition, modern casper metadata requirement, and post-patch redetection are appropriate for the current experimental contract. Broader distribution coverage belongs in versioned fixtures rather than relaxed heuristics.

## Acquisition and update channel

### A-021 — threshold channel core is strongly bounded

**Severity:** none  
**Status:** cleared

The built-in channel uses canonical JSON, threshold Ed25519 roles, sequential dual-authorized root rotation, rollback and expiry checks, owner-only state, verified cache fallback, exact sizes, redirect-host constraints, and SHA-256. Production remains correctly disabled until reviewed offline keys and metadata exist.

### A-022 — downloaded-file destination should use descriptor-based existing-file checks

**Severity:** low  
**Status:** deferred

After atomic no-replace is implemented, existing-file verification can also use a no-follow descriptor rather than separate `Lstat` and open operations. This is primarily same-user hardening.

## Packaging, CI, and supply chain

### A-023 — GitHub Actions are referenced by mutable tags

**Severity:** high supply-chain hardening  
**Status:** fixing

`checkout`, `setup-go`, artifact actions, and release actions use major-version tags. Pin them to reviewed commit SHAs with update comments.

### A-024 — release workflow grants write permission to all jobs

**Severity:** medium  
**Status:** fixing

Move `contents: write` to the release job only. Keep build/test jobs read-only and add explicit job timeouts and workflow concurrency.

### A-025 — missing static and packaging validators

**Severity:** medium  
**Status:** fixing or staged

Add pinned/controlled runs for:

- `staticcheck` and `govulncheck`;
- `shellcheck`;
- `actionlint`;
- `desktop-file-validate` and `appstreamcli validate`;
- `lintian` on the resulting Debian package.

New tools must be version-pinned and must not make releases depend on mutable download scripts.

### A-026 — source defaults report stale release versions

**Severity:** low semantics  
**Status:** fixing

Unpackaged Go/Python source reports `0.9.0`, while package builds replace it. Change source fallbacks to `development`; continue stamping the canonical release version through linker flags and the package build.

## Documentation and parity process

### A-027 — parity inventory baseline is stale

**Severity:** medium process  
**Status:** fixing before rebase

The pending parity inventory says project baseline `0.10.1`, while the audited baseline is `0.10.4`. It also labels persistence simply `implemented` despite the explicit physical-qualification gate. Update statuses to distinguish code-complete, packaged, and physically qualified behavior.

### A-028 — documentation must distinguish verification layers

**Severity:** medium semantics  
**Status:** fixing

Use separate terms for:

- source identity verification;
- copied-byte/file verification;
- filesystem structural checks;
- bootloader structure/DBX checks;
- physical boot qualification;
- persistence reboot qualification.

A successful write must never imply firmware boot or Secure Boot acceptance.

## Cleared implementation areas

The audit found substantial good practice that should be preserved:

- source files are pinned by device/inode/size/mtime/ctime and held open;
- Windows ISOs and prepared containers are hashed before and after expensive work;
- whole targets are locked and verified by `dev_t` plus live capacity ioctl;
- system disks, protected mounts, active swap, partitions, read-only targets, and most fixed media are refused;
- persistent-media copying is entry/byte bounded, FAT32-aware, symlink-averse, hashed, and rehashed;
- persistence boot patching uses no-follow descriptor traversal and atomic replacement;
- GPT persistence creation verifies primary and backup metadata;
- cancellation uses a private runtime marker and protected process-group termination;
- the package separates the ordinary and persistence privileged helpers;
- acquisition metadata is strict, canonical, threshold-signed, expiry-bounded, and rollback-resistant;
- CI already includes race tests, shuffled tests, vet, coverage, Python tests, cross-builds, native ARM64 execution, and package-content checks.

## Audit completion gate

Feature development resumes only after:

1. all `fixing` items are closed or explicitly downgraded with rationale;
2. full x86-64 audit/package CI passes;
3. native ARM64 tests execute both packaged helpers;
4. the package file list, runtime versions, desktop/Polkit metadata, bundled WIM engine, UEFI:NTFS image, and checksums are independently inspected;
5. the four pending 0.11 UEFI/parity files are rebased onto this branch and re-reviewed;
6. unresolved `deferred` items are represented in the parity inventory and issue tracker rather than silently forgotten.
