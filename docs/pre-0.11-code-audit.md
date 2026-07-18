# Pre-0.11 full-code audit

Date: 2026-07-17

Baseline: `7b10e134b83fca3c82f5dc354f844cee4ed2c557` (`0.10.4`)

Audit disposition at the current branch head:

- **24 fixed findings** with code, regression coverage, or permanent CI/package gates;
- **3 cleared findings** where the original concern did not represent a defect;
- **4 explicit architectural or trust deferrals** that do not weaken the current documented release contract;
- **2 planned parity items** that remain outside this corrective branch.

The branch is not considered release-ready merely because software CI passes. Persistent-live support still requires physical boot and reboot qualification for each claimed image/hardware combination.

This document is the release gate for resuming Rufus-parity work. It reviews the Linux-native implementation from destructive-operation safety, privilege separation, source and target identity, parser robustness, integer arithmetic, external-command execution, concurrency and cancellation, performance, packaging, CI, documentation, and upstream-Rufus parity perspectives.

Statuses:

- **confirmed** — demonstrated directly from the current call chain or by a focused regression case;
- **fixed** — corrected with regression coverage or a permanent validation gate;
- **fixing** — accepted for the audit branch and requires code plus tests;
- **deferred** — valid hardening work that is too broad to mix into a small corrective commit;
- **cleared** — investigated and not a defect;
- **planned** — parity work, not a regression in the released contract.

## Release blockers

### A-001 — target identity is relaxed after confirmation

**Severity:** critical safety hardening  
**Status:** fixed

The ordinary writer and dedicated persistence helper validate the GUI-provided target identity initially, but later callbacks call `RevalidateTarget` with an empty expected identity. The identity token intentionally excludes the child partition layout, so it remains valid across wiping, partitioning, and formatting. Dropping it weakens protection against disconnect/reconnect or `/dev/sdX` reuse during a long preparation or creation operation.

Implemented correction:

- retain the selected identity through every pre-destructive and post-layout revalidation;
- keep open-descriptor `dev_t` and capacity checks as an independent second boundary;
- add tests proving partition-layout changes do not alter a whole-disk token, while disk sequence and device identity changes do.

### A-002 — unchecked capacity arithmetic in untrusted-media planning

**Severity:** high  
**Status:** fixed

Several image and Windows-media calculations use unchecked `uint64` addition or alignment arithmetic. The practical values of ordinary images are small, but parsers and sparse files are attacker-controlled. Overflow can produce a falsely small required capacity, incorrect progress totals, or an invalid offset.

Affected classes include:

- decompressed-byte counters and size-limit writers;
- Windows ISO, split-WIM, answer-file, and driver-folder totals;
- GPT alignment and partition-end calculations;
- Linux-media aligned byte/sector conversions;
- image-sector rounding near the signed file-size limit.

Implemented correction:

- centralize checked add, multiply, subtract, and align-up helpers;
- fail before target erasure on overflow;
- add boundary and malicious-size regression tests.

### A-003 — privileged executable and asset overrides are environment-selected

**Severity:** high defense in depth  
**Status:** fixed

The Windows-media engine accepts `RUFUSARM64_WIMLIB` before package-owned candidates, and the graphical launchers accept helper-path environment overrides. Normal `pkexec` deployments commonly sanitize the environment, and a root caller can already execute arbitrary programs, but privileged code should not depend on that assumption.

Implemented correction:

- production GUI launchers use package-owned helper paths;
- the privileged WIM resolver uses the executable-adjacent package asset, the pinned package path, then a trusted system `PATH` fallback;
- test injection uses explicit package-level hooks or test-only controls rather than production environment overrides;
- keep the UEFI:NTFS checksum pin even for development candidates.

### A-004 — Windows media traversal is not bounded by entry count

**Severity:** high availability and preflight robustness  
**Status:** fixed

Persistence media inspection has explicit entry and byte ceilings. Windows ISO and driver-folder walks reject special files and links but have no entry-count ceiling, and some byte totals are unchecked. A pathological image can consume excessive time and memory before the destructive boundary.

Implemented correction:

- cap Windows ISO and driver-folder entries with conservative documented limits;
- use checked totals tied to the selected target capacity;
- preserve support for normal Microsoft media and large driver sets;
- add over-limit and overflow tests.

### A-005 — no-replace acquisition can overwrite a file created during download

**Severity:** medium correctness  
**Status:** fixed

When replacement is disabled, the destination is checked before transfer, but the final same-directory `rename` can replace a file created after that check. This violates the command's no-replace contract.

Implemented correction:

- use an atomic no-replace installation primitive on Linux;
- keep temporary data in the destination directory;
- sync the file and parent directory;
- add a race-contract regression test.

## Privilege and destructive-operation hardening

### A-006 — Polkit policy permits inactive and nonlocal authentication

**Severity:** medium  
**Status:** fixed

The package-owned helpers are intended for active graphical sessions. `allow_any` and `allow_inactive` currently request administrator authentication rather than denying those contexts.

Implemented correction:

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

### A-008 — Windows GPT metadata receives durable exact readback verification

**Severity:** medium  
**Status:** fixed

The Windows GPT creator now validates signed-offset bounds, rejects short writes, writes and syncs backup metadata before primary metadata, and reads the protective MBR, both headers, and both entry arrays back byte-for-byte before success. Focused tests cover durability order, corrupted readback, short writes, and oversized offsets.

### A-009 — legacy systems can expose weaker whole-disk identity

**Severity:** low to medium  
**Status:** deferred

The identity token includes `MAJ:MIN`, `diskseq`, serial, WWN, size, model, vendor, transport, and policy flags. On older kernels or inexpensive USB bridges, `diskseq`, serial, and WWN can all be absent. Add stable sysfs/USB topology identifiers where available, while retaining open-descriptor identity and capacity checks.

### A-032 — kernel-exclusive partition descriptors block inherited filesystem tools

**Severity:** high destructive-path correctness
**Status:** fixed

The persistent-media creator opened each new partition with `O_EXCL`, then passed that descriptor to `mkfs.vfat`, `mkfs.ext4`, `mount`, and filesystem checkers through `/proc/self/fd/3`. Those tools reopen the inherited path. On a real Linux block device, the creator's existing kernel-exclusive holder makes the trusted reopen fail with `EBUSY` after the new GPT has already replaced the previous media layout.

Implemented correction:

- retain `O_NOFOLLOW`, the parent whole-disk lock, the partition advisory `flock`, and all descriptor identity, size, geometry, and parent-disk checks;
- omit kernel `O_EXCL` only for descriptors intentionally inherited by trusted filesystem tools;
- keep every external command bound to the already-verified descriptor rather than returning to the user-supplied partition pathname;
- add a permanent root-only loop-device CI regression that formats, checks, mounts, writes, and unmounts FAT32 and ext4 through inherited `/proc/self/fd/3` handles.

The resulting failure mode remains explicit: media interrupted before filesystem creation is incomplete and must be recreated. No software-only test changes the separate physical boot and persistence qualification requirement.

### A-033 — persistent GPT partitions permit a desktop automount race

**Severity:** high destructive-path correctness
**Status:** fixed

A physical Surface Pro 11 and USB retest still reached `mkfs.vfat` with `EBUSY` after A-032 removed the creator's kernel-exclusive partition open. A partitioned-loop diagnostic then proved that the long-held, flocked parent-disk descriptor does not block a formatter reopening the child partition. The remaining host race was that both newly published GPT entries had all attribute bits clear, allowing desktop storage services to automount a stale or newly recognized filesystem between RufusArm64's explicit unmount verification and the formatter's exclusive open.

Implemented correction:

- set GPT attribute bit 63 (do not automount) on both the FAT32 boot partition and ext4 persistence partition before the kernel partition-table reread;
- include the attribute in exact primary and backup GPT entry-table readback verification;
- retain the whole-disk lock, partition `flock`, no-follow descriptors, device identity and capacity checks, exact geometry verification, and parent-device binding;
- release the correction as 0.10.6 so an installed 0.10.5 package is upgraded normally rather than ambiguously reinstalled.

The do-not-automount attribute prevents host desktop policy from claiming the partitions during creation. It does not change their firmware boot type, filesystem format, or normal mountability after the USB is complete.

## GUI, semantics, and concurrency

### A-010 — packaged GUI is rewritten by string substitution

**Severity:** high maintainability and test fidelity  
**Status:** fixed

`build-deb.sh` mutates persistence labels and explanatory text after copying the tested Python source. The installed application therefore differs from the source exercised by normal Python tests, and harmless wording refactors can break packaging.

Implemented correction:

- put the shipped wording and controls directly in `gui/rufusarm64.py`;
- remove package-time semantic replacements;
- restrict package stamping to the version constant;
- test the source and installed GUI for the same persistence boundary.

### A-011 — one visible icon still hides the real creator too deeply

**Severity:** medium usability  
**Status:** fixed

Desktop actions are not obvious in every GNOME application-grid interaction. Add a direct **Open Persistent USB Creator** control inside the single visible RufusArm64 window. It must launch the guarded wizard and must not silently change the ordinary **Create USB** button's mode.

### A-012 — slow GUI probes no longer block the GTK thread

**Severity:** medium performance and responsiveness  
**Status:** fixed

Image inspection, removable-device enumeration in both windows, and manual signed-catalog verification now run in worker threads. Monotonic generation tokens, selected-path snapshots, and close guards prevent stale callbacks from replacing newer selections or touching a destroyed window. A permanent AST-based test rejects regression to synchronous GTK callbacks.

### A-013 — DBX update is asynchronous but not part of the GUI busy state

**Severity:** medium concurrency  
**Status:** fixed

A DBX download can run while a write is started. The completion callback may change the selected DBX path during another operation. Give DBX acquisition its own task token or include it in the shared busy state, and ignore stale completions.

### A-014 — settings-file update is not fully durable or symlink-averse

**Severity:** low  
**Status:** fixed

The GUI uses a predictable `.tmp` path and atomic replace but does not create a unique no-follow temporary file or sync the containing directory. The directory is normally private, so impact is limited to the same user.

Implemented correction:

- create a unique temporary file in the private config directory;
- set mode before exposing content;
- flush the file and parent directory;
- replace atomically and reject an unsafe config directory.

### A-029 — GUI worker process ownership and early cancellation

**Severity:** medium concurrency and cancellation  
**Status:** fixed

Each graphical worker owns a local process reference and clears the shared reference only when it still points to that child. Verified downloads also honor cancellation immediately after `Popen`. A permanent source-structure test covers all five workers.

### A-030 — existing verified-download pathname race

**Severity:** medium trust semantics  
**Status:** fixed

Reused downloads are opened without following links, compared with the original inode before hashing, checked for mutation, and compared with the final pathname. Replacement and symlink-swap tests fail closed.

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
**Status:** fixed

`(size + 511) / 512` can overflow near `MaxInt64` for a sparse file. Use division plus remainder without signed addition.

### A-018 — 0.11 UEFI scanner bounds only EFI-file count

**Severity:** medium  
**Status:** deferred

The pending UEFI validator limits discovered `.efi` files but can walk an unbounded number of unrelated paths. Add a total-entry ceiling, reject duplicate `.sbat` sections, validate all relevant PE section extents, and reduce parser duplication with the existing Authenticode code where practical.

### A-019 — DBX update authenticity is structural plus HTTPS, not signer verification

**Severity:** medium trust semantics  
**Status:** deferred

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

### A-022 — reused downloads are bound to the opened regular inode

**Severity:** low to medium same-user hardening  
**Status:** fixed

Existing downloads are opened with `O_NOFOLLOW`, compared with the original `Lstat` identity before hashing, checked for mutation after hashing, and compared again with the final pathname. Replacement and symlink-swap regression tests fail closed. Atomic no-replace installation remains the separate boundary for newly downloaded files.

## Packaging, CI, and supply chain

### A-023 — GitHub Actions are referenced by mutable tags

**Severity:** high supply-chain hardening  
**Status:** fixed

`checkout`, `setup-go`, artifact actions, and release actions use major-version tags. Pin them to reviewed commit SHAs with update comments.

### A-024 — release workflow grants write permission to all jobs

**Severity:** medium  
**Status:** fixed

Move `contents: write` to the release job only. Keep build/test jobs read-only and add explicit job timeouts and workflow concurrency.

### A-025 — missing static and packaging validators

**Severity:** medium  
**Status:** fixed

Add pinned/controlled runs for:

- `staticcheck` and `govulncheck`;
- `shellcheck`;
- `actionlint`;
- `desktop-file-validate` and `appstreamcli validate`;
- `lintian` on the resulting Debian package.

New tools must be version-pinned and must not make releases depend on mutable download scripts.

### A-026 — source defaults report stale release versions

**Severity:** low semantics  
**Status:** fixed

Unpackaged Go/Python source reports `0.9.0`, while package builds replace it. Change source fallbacks to `development`; continue stamping the canonical release version through linker flags and the package build.

### A-031 — package reproducibility and Debian policy were not release gates

**Severity:** medium supply-chain and maintainability  
**Status:** fixed

CI builds the deterministic Debian package twice and requires byte-for-byte equality. Lintian, AppStream, desktop validation, machine-readable copyright, runtime dependencies, changelog, man pages, and narrow static-helper overrides are permanent gates.

## Documentation and parity process

### A-027 — parity inventory baseline is stale

**Severity:** medium process  
**Status:** planned

The pending parity inventory says project baseline `0.10.1`, while the audited baseline is `0.10.4`. It also labels persistence simply `implemented` despite the explicit physical-qualification gate. Update statuses to distinguish code-complete, packaged, and physically qualified behavior.

### A-028 — documentation and completion messages distinguish verification layers

**Severity:** medium semantics  
**Status:** fixed

User-facing documentation and completion messages distinguish source identity, copied bytes/files, filesystem consistency, bootloader/DBX structure, physical firmware boot, and persistence across reboot. A successful software write never claims universal firmware boot or Secure Boot acceptance.

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

## Final gate and accepted deferrals

One unchanged commit must pass Go 1.22 compatibility, formatting, race and shuffled tests, vet, coverage, Python and GUI-structure tests, Staticcheck, Govulncheck, Actionlint, ShellCheck, AppStream, desktop validation, Lintian, deterministic package comparison, package inspection, and native ARM64 execution.

Accepted deferrals are descriptor propagation to compatible external tools (A-007), stronger legacy-device topology identity (A-009), rebase of the stacked 0.11 validator and inventory (A-018 and A-027), Microsoft DBX signer verification before stronger authenticity claims (A-019), and newer Windows/Rufus parity work (A-016).

Persistent-live support remains experimental until physical boot and reboot qualification is published for each claimed image and hardware combination.
