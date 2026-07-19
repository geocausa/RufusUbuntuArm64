# RufusArm64 0.12.0 focused code audit

This audit replaces the pre-release physical sanity pass at the owner's request. It reviews the Stage 1 drive-image backup delta, its privilege boundary, process lifecycle, report protocol, package isolation, and canonical release automation. Existing full Go, Python, static, vulnerability, loop-device, reproducibility, and native ARM64 gates remain mandatory.

## Findings corrected

1. **Privileged destination creation:** the graphical helper could create a new image in a directory the desktop user could not write without elevation. The release now requires write and search permission for the authenticated desktop user on the held destination directory before the source is opened.
2. **Progress-channel failure after successful copy:** a broken JSON progress pipe could previously permit publication and then return an error. Progress output failure now cancels the copy context before synchronization and publication, so temporary output is removed.
3. **Exceptional GTK process lifecycle:** malformed progress or report data could request termination without waiting for the owned privileged process group to exit. Exceptional paths now terminate, drain, escalate if necessary, and reap the process group before the application busy state is released.
4. **Fail-open report details:** successful reports could carry a failure object, failed reports could omit one, and non-integral JSON numbers could be coerced. Report parsing now requires exact integers and status-consistent failure, exit-status, file-type, size, and ownership data.

## Reviewed invariants retained

- exact removable-source identity and kernel-device binding;
- running-root-disk and protected-mount refusal;
- read-only exclusive source open and guarded unmounting;
- destination-on-another-disk and free-space preflight;
- new-path-only publication using `renameat2(RENAME_NOREPLACE)`;
- incomplete-output cleanup, source/destination revalidation, synchronization, SHA-256 reporting, and desktop-user handoff;
- isolated packaged Python launcher and package-owned privileged commands;
- version synchronization, immutable canonical tag creation, release workflow dispatch, and read-only published-release verification.

## Residual boundary

Software and CI evidence cannot establish universal USB-controller, firmware, filesystem-mount, or physical-media behaviour. Field observations are accepted as 0.12.x defect reports while Stage 2 proceeds toward 0.13.0.
