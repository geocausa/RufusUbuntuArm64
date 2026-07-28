# RufusArm64 0.15.0 hardware and prerelease checklist

This record gates promotion of the 0.15.0 candidate. Software and loop-device evidence are necessary but do not replace the physical ARM64 observations below.

## Candidate identity

- Candidate commit: to be recorded after the release-contract PR is merged.
- Prerelease tag: to be recorded after publication.
- Debian package filename and SHA-256: to be recorded after publication.
- Source archive SHA-256 and publication workflow: to be recorded after publication.
- Tester, date, host, kernel, firmware, Secure Boot state, source-image identity, USB model/path/capacity: to be recorded for every physical run.

## Installation and desktop smoke

- [ ] Verify the downloaded SHA-256 sidecar independently.
- [ ] Install or upgrade `rufusarm64_0.15.0~rc1_arm64.deb` on an ARM64 machine.
- [ ] Confirm package, CLI, helper, and graphical About versions are `0.15.0~rc1`.
- [ ] Launch the composed graphical application and confirm the ordinary writer and existing specialist entry points still open.

## ISO Image mode choice

Use a disposable or fully backed-up removable USB and a known Linux ARM64 ISOHybrid image.

- [ ] Select a compatible ISOHybrid image and confirm a visible **ISO Image mode / DD Image mode** choice appears.
- [ ] Confirm **ISO Image mode (Recommended)** is selected by default.
- [ ] Confirm **DD Image mode** remains selectable and is described as the exact byte-for-byte alternative.
- [ ] Cancel the choice dialog and confirm no target mutation occurs.
- [ ] Confirm an unsupported image does not receive a misleading ISO-mode offer or silent destructive fallback.

## ISO Image mode creation and physical boot

- [ ] Create the USB in ISO Image mode and record the exact source and target identities shown before authentication.
- [ ] Confirm the operation reports complete copied-file verification, FAT32 checking, synchronization, and success.
- [ ] Independently inspect the completed USB: one active MBR FAT32-LBA partition, expected label, native `EFI/BOOT/BOOTAA64.EFI`, and representative files matching the source.
- [ ] Confirm the FAT32 filesystem is conventionally writable by creating, reading, hashing, deleting, and synchronizing a harmless test file.
- [ ] Boot the Surface Pro 11 from the USB and record the first visible Ubuntu boot/live-session evidence.
- [ ] Confirm ordinary live boot works without claiming persistence; ISO Image mode does not create a persistence partition.
- [ ] Record any firmware, Secure Boot, driver, display, input, networking, storage, or shutdown limitation separately from the media-write result.

## DD regression and refusal behavior

- [ ] Where practical, write the same image in DD Image mode to disposable media and confirm the existing direct-write behavior remains available and bootable on the bounded test host.
- [ ] Confirm source or target change invalidates the reviewed destructive plan.
- [ ] Confirm sustained target-lock contention fails before mutation; short-lived contention may retry only within the bounded cancellable window.
- [ ] Confirm cancellation before erasure leaves the target unchanged and cancellation/failure after erasure is never reported as success.
- [ ] Confirm system/root disks, protected mounts, partitions, read-only targets, and normal fixed disks remain refused or absent from selection.

## Existing workflow regression

- [ ] Confirm at least one previously qualified ordinary function still works after upgrade, such as checksums, data-only formatting, persistence entry, drive backup, FreeDOS entry, or Check USB.
- [ ] Keep the 0.14.0 qualification evidence bounded to its exact candidate; do not relabel it as 0.15.0 evidence.
- [ ] Physical FFU restoration remains untested unless authentic supported FFU material and suitable disposable hardware become available.

## GO / NO-GO

- [ ] Every exercised observation is recorded with exact hardware, media, candidate, image, tester, date, result, and evidence.
- [ ] Every unexercised item is marked **UNTESTED**, not passed.
- [ ] Blocking defects are fixed on a new candidate and affected observations are repeated.
- [ ] A bounded GO/NO-GO decision is recorded for this exact candidate without universal firmware, Secure Boot, distribution, controller, flash-health, or FFU claims.

Until this record is complete, 0.15.0 remains a prerelease candidate rather than a stable hardware-qualified release.
