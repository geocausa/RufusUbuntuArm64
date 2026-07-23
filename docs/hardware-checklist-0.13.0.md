# RufusArm64 0.13.0 real-machine sanity checklist

This checklist is the human publication gate for the 0.13.0 release candidate. It records observations on exact hardware; it does not create universal compatibility claims.

## Record the environment

- [ ] Release-candidate commit SHA recorded.
- [ ] `rufusarm64_0.13.0_arm64.deb` SHA-256 recorded and matches the CI artifact.
- [ ] Ubuntu release, kernel, desktop, firmware version, Secure Boot state, machine model, CPU, USB controller, USB make/model/capacity, and connection path recorded.
- [ ] Diagnostic report saved before and after testing.
- [ ] Test USB contains no needed data.

## Package and interface

- [ ] Package installs or upgrades successfully with `apt`.
- [ ] One RufusArm64 desktop entry opens the GTK 3 application.
- [ ] Boot image and USB target can be reached by keyboard mnemonics.
- [ ] Ctrl+R, Ctrl+D, Ctrl+K, Ctrl+U, and F1 open only their documented non-destructive actions.
- [ ] No shortcut bypasses the final erase confirmation.
- [ ] Compatibility, progress details, and diagnostics are readable and selectable.
- [ ] Copy and Save diagnostic actions produce a useful report without secrets or stale operation state.
- [ ] On a 1280×800 work area, **Restore / format…**, **Check USB**, **Save drive image…**, and **FreeDOS…** keep confirmation, progress, action, and Close controls visible while long plan and report text remains scrollable.

## Ordinary Linux image

Use a checksum-verified ARM64 Linux ISOHybrid image appropriate for the test computer.

- [ ] The image is recognized before a target is selected.
- [ ] Hybrid/raw versus optical-only status and any El Torito/bootloader details are plausible.
- [ ] The exact removable target identity, model, and capacity are shown.
- [ ] Create USB defaults the destructive dialog to Cancel.
- [ ] Writing, flush, and verification complete without removing the drive.
- [ ] The produced USB is observed in firmware and boots on the recorded computer.
- [ ] A successful software check is not recorded as proof for other hardware.

## Windows ARM64 media

Use an official checksum-verified Windows ARM64 installation ISO.

- [ ] GPT / UEFI is selected; BIOS/CSM is unavailable for ARM64 media.
- [ ] Edition count/names and WIM, ESD, or split-SWM payload facts match the ISO.
- [ ] Unsupported setup options are disabled rather than guessed.
- [ ] Automatic/FAT32 or the deliberately selected NTFS path is explained before erasure.
- [ ] Creation and requested copied-file verification complete.
- [ ] Firmware sees the USB and Windows Setup starts on the recorded ARM64 computer.
- [ ] Optional answer-file choices are observed only when explicitly selected.

## Persistent Ubuntu or Debian media

Complete this section only when claiming persistence for this hardware/image pair.

- [ ] Read-only analysis succeeds for the exact selected image, target, and size.
- [ ] The fresh GPT/FAT32/ext4 plan and boot files to be changed are reviewed.
- [ ] Creation completes and both filesystems pass checks.
- [ ] `rufusarm64-cli qualify start` produces a valid initial report and checksum.
- [ ] A harmless persistent change is made.
- [ ] The same USB is rebooted on the same computer and the change survives.
- [ ] `rufusarm64-cli qualify verify` produces a passing report and checksum.
- [ ] Secure Boot state and use/non-use of the unsigned boot-time validator are recorded explicitly.

## Data-only restore and ordinary reuse

- [ ] **Restore / format…** calculates a fresh unprivileged plan for the exact selected USB.
- [ ] The FORMAT phrase includes the intended device and filesystem.
- [ ] One chosen GPT/MBR and filesystem combination completes and passes readback/filesystem checks.
- [ ] The restored drive accepts ordinary file creation, readback, deletion, safe removal, and reconnection.
- [ ] No bootability claim is shown for data-only media.

## FreeDOS platform and fast-creation boundary

Use a disposable removable drive and, separately, an x86-compatible BIOS or UEFI-Legacy/CSM test computer.

- [ ] The GTK plan states FreeDOS 1.4, x86 only, BIOS/UEFI-Legacy only, and not ARM64/UEFI-only.
- [ ] The exact `WRITE FREEDOS 1.4 TO /dev/DEVICE FOR X86 BIOS LEGACY` phrase is required.
- [ ] The plan shows required write bytes, required verification bytes, and untouched unallocated bytes before authentication.
- [ ] On a normal-capacity target such as 16–32 GiB, total displayed FreeDOS I/O is bounded by the required boot/FAT32 extents and is far below twice the device capacity.
- [ ] Creation completes with required-extent readback and extent-set SHA-256 reporting.
- [ ] The result keeps a nearly full-size FAT32 partition even though unallocated data clusters are not overwritten.
- [ ] The final report does not claim whole-device health and directs exhaustive testing to **Check USB**.
- [ ] The drive is not tested as an ARM64 or UEFI-only boot path.
- [ ] Any physical boot observation records the exact x86 computer and firmware mode; no universal claim is made.

## Verified acquisition

The upstream production channel is expected to remain disabled for this candidate.

- [ ] The disabled built-in channel reports its boundary and does not offer an unsigned bypass.
- [ ] A separately trusted local catalogue, detached signature, and public key can be inspected.
- [ ] A deliberately interrupted download leaves no installed unverified image.
- [ ] Retrying resumes only a compatible owner-private SHA-bound partial.
- [ ] Completion verifies signed size and SHA-256, installs atomically, and selects the image for normal inspection.
- [ ] Destination collision behavior does not replace an existing file silently.

## Backup, post-operation actions, and cancellation

- [ ] **Save drive image…** reads the source only, publishes no partial file, and reports SHA-256.
- [ ] Successful creation offers **Create another USB** while retaining the image.
- [ ] Successful creation offers restoration for the exact completed target without erasing automatically.
- [ ] Cancel before authentication leaves media unchanged.
- [ ] Cancel during a destructive operation waits for final cleanup/reporting and marks changed incomplete media conservatively.
- [ ] Closing the main window is refused while an operation is active.
- [ ] The application returns to an idle usable state after success, refusal, cancellation, and failure.

## Publication decision

- [ ] Every failed item has a linked issue, retained diagnostic report, and explicit disposition.
- [ ] No unresolved defect can select, erase, publish, or qualify the wrong source or target.
- [ ] No release text claims whole-device FreeDOS qualification from required-extent creation.
- [ ] No release text claims Secure Boot compatibility for the unsigned runtime-integrity loader.
- [ ] No release text claims universal physical boot success.
- [ ] Production acquisition remains disabled unless separate offline-key and mirror provisioning evidence is approved.
- [ ] Maintainer records **GO** or **NO-GO**, date, tester, exact commit, and artifact SHA-256 below.

## Signed-off result

- Decision:
- Date:
- Tester:
- Computer and firmware:
- Release-candidate commit:
- Package SHA-256:
- Evidence/issue links:
- Notes:
