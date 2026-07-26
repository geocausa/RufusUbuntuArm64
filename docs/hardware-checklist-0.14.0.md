# RufusArm64 0.14.0 hardware and prerelease checklist

This record gates promotion of the 0.14.0 candidate. Software CI evidence is necessary but is not a substitute for the physical observations below.

## Candidate identity

- Candidate commit: to be recorded after the release-contract PR is merged.
- Prerelease tag: to be recorded after publication.
- Debian package filename and SHA-256: to be recorded after publication.
- Test host: Ubuntu ARM64.

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
