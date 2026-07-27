# RufusArm64 0.14.0 hardware and prerelease checklist

This record gates promotion of the 0.14.0 candidate. Software CI evidence is necessary but is not a substitute for the physical observations below.

## Candidate identity

- Candidate commit: `5d0f9ea97af8c055df2a9412b491b9888ec8f665`.
- Prerelease tag: `0.14.0-rc1`.
- Debian package: `rufusarm64_0.14.0~rc1_arm64.deb`.
- Debian package SHA-256: `a47a361d362f3f13357f8f180e608ba78a583e923c2aed6dc45e46550063f1a5`.
- Source archive SHA-256: `5ffa17704d0a1577495b1166ff93f008c434c78f8a1ac22ff2d76ab5e2de8565`.
- Authenticated publication workflow: run `30225915981`.
- Required test platform: Ubuntu ARM64; record the exact machine, kernel, firmware, package source, and removable-media identity for each observation.

## Established software evidence

The following evidence is bound to the candidate identity above. It does not check any physical-observation box in this record.

- [x] Go 1.22 compatibility, full test/audit, native ARM64 execution, packaged-binary execution, privileged raw/VHD/VHDX/ISO-UDF qualification, formatter, FreeDOS, UEFI, FFU software audit, and reproducible Debian packaging passed for the release-candidate tree.
- [x] The prerelease publication independently rebuilt the pinned ARM64 WIM engine and unsigned UEFI integrity loader.
- [x] The `0.14.0~rc1` Debian package was reproduced byte-for-byte before publication.
- [x] Published package identity, source identity, tag target, checksums, and release evidence were authenticated by the publication workflow.

## Observation recording rule

For every exercised item, record the tester, UTC date, exact host/kernel/firmware, source package checksum, source and target device identities, command or graphical path, result, and evidence location. Mark an item **untested** rather than passed when the required hardware, firmware, image, or disposable media is unavailable.

## Installation and desktop smoke test

- [ ] Verify the downloaded SHA-256 sidecar.
- [ ] Install or upgrade the prerelease package on an ARM64 machine.
- [ ] Launch RufusArm64 from the desktop and terminal.
- [ ] Confirm the displayed/package/helper version matches the prerelease package.
- [ ] Confirm the normal writer, persistence, Restore / format…, FreeDOS…, Check USB, Save drive image…, and experimental FFU entry points open without import or layout failure.

## Drive backup

Use disposable or fully backed-up removable media and a destination on a different physical disk.

- [ ] Raw capture completes, reports the expected source identity/capacity and SHA-256, and an independent byte comparison matches.
- [ ] Dynamic VHD capture completes and independent tooling sees the expected virtual capacity/content.
- [ ] Dynamic VHDX capture completes, passes consistency validation, and independent tooling sees the expected virtual capacity/content.
- [ ] Filesystem ISO/UDF capture completes from one mounted representative filesystem and an independent UDF mount exposes matching files and hashes.
- [ ] Existing destination refusal is observed for every exercised format.
- [ ] Cancellation removes partial output and leaves no published success claim.
- [ ] ISO/UDF limitations are visible: no partition-table, hidden-sector, unallocated-space, extra-filesystem, or bootability claim.

## Experimental FFU

- [ ] Unsupported, malformed, unsigned/untrusted, or wrong-profile FFU sources are refused before target mutation.
- [ ] Dry-run binds the exact source evidence, target path, target identity, and capacity.
- [ ] Exact destructive confirmation cannot be reused after source or target changes.
- [ ] If a disposable supported single-store-v1 image and target are available, complete restore, flush, readback, and final evidence pass.
- [ ] No vendor-device, OEM recovery, firmware boot, or broad FFU compatibility claim is recorded from software-only evidence.

## Existing workflow regression

- [ ] Create and boot representative Ubuntu ARM64 media on the intended ARM64 host.
- [ ] Create Windows ARM64 installation media and reach the expected UEFI setup environment where practical.
- [ ] Create persistent Ubuntu/Debian media, save a harmless change, reboot, and confirm retention.
- [ ] Create and verify data-only storage media on at least one supported filesystem.
- [ ] Create FreeDOS media and confirm the final required-extent report; physical x86 BIOS/Legacy boot remains separately recorded if hardware is available.
- [ ] Run quick or full Check USB only on disposable media and export the identity-bound report.

## Failure and safety observations

- [ ] System/root disks and protected mounts remain refused.
- [ ] Fixed disks remain absent from normal graphical selection.
- [ ] Destructive dialogs default to Cancel and show exact device/source identities.
- [ ] Cancelling before destructive authorization leaves the target unchanged.
- [ ] A failure after destructive work is reported conservatively and never as success.
- [ ] The unsigned UEFI integrity loader and Secure Boot limitation remain visible.

## GO / NO-GO

- [ ] All exercised package, backup, FFU-boundary, and regression observations are recorded with exact hardware/media identities.
- [ ] Any untested item is explicitly marked untested rather than passed.
- [ ] Blocking defects are fixed on a new candidate and the affected observations repeated.
- [ ] GO decision for stable promotion is signed off with candidate commit, tag, package SHA-256, tester, date, and bounded claims.

Until that record is complete, 0.14.0 remains a prerelease candidate rather than a stable hardware-qualified release.
