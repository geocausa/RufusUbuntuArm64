# Rufus 4.15 regression tranche

This tranche closes bounded parity regressions against pinned upstream Rufus 4.15 commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`. Rufus's `GetFsName()` behavior in `src/drive.c` is the direct SquashFS-detection reference; Linux-native safety policy remains independently enforced.

Delivered software boundary:

- direct byte-zero SquashFS `hsqs` recognition, while a bare filesystem image remains refused for automatic raw writing unless the operator deliberately selects `--force-raw`;
- validated optical or coherent GPT/MBR evidence takes priority over a coincidental SquashFS hint in an ISO system area;
- case-insensitive WIM/ESD/SWM payload classification with case-collision, critical symlink, conflicting-family, missing-part, duplicate-part, and 1,024-part-bound refusals;
- a pure, explicit-boolean GTK runtime-validation enablement rule that permits the development option only after successful analysis and while the UI is idle;
- cancellation checks before every repeated partial write in both target writing and private compressed-image materialization;
- authenticated, bounded ZIP and sequential-compression progress and cancellation regressions.

These changes preserve the existing source/target identity, pre-erasure revalidation, synchronization, readback, and report boundaries. Physical-media and universal compatibility claims remain outside this software-only tranche.
