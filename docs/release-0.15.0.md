# RufusArm64 0.15.0 development notes

Status: Stage 4 development branch; not a published release.

## Completed software tranches

- Guarded ext2 and ext3 data-only formatting through the existing GPT/MBR planner, exact identity binding, exact `FORMAT` confirmation, e2fsprogs creation, forced read-only `e2fsck -f -n`, exact filesystem/geometry/label readback, GTK integration, and real loop-device qualification.
- Application-scoped GTK appearance selection with canonical **System**, **Light**, and **Dark** modes.
- Complete main-window option and primary-action tooltips, applied after every composed integration while preserving more specific existing disclosures.
- A bounded GNU gettext runtime and deterministic `po/rufusarm64.pot` source catalog for primary-window headings, labels, actions, appearance wording, main-control tooltips, and related accessibility metadata.

## Appearance, tooltip, and localization contract

- **System** is the default and restores the GTK light/dark preference observed when RufusArm64 started.
- **Light** and **Dark** affect only the current RufusArm64 process and its dialogs.
- The canonical setting is stored in the existing owner-private settings JSON as `appearance: system|light|dark`.
- Missing, malformed, and unknown values resolve to **System**.
- The selector is exposed from the main header bar with tooltips and assistive-technology metadata.
- Every main image, target, persistence, Windows-layout, diagnostics, appearance, and primary action control has a bounded purpose/safety tooltip.
- Tooltip completion runs only after the complete composed window exists and never replaces a more specific tooltip supplied by an individual workflow.
- Localization loads the standard `rufusarm64` gettext domain and safely keeps the reviewed English source text when no valid catalog exists.
- Translation runs after composed construction and tooltip completion, and only exact admitted static messages are eligible.
- Machine-readable JSON, command flags, paths, identities, filesystem planner values, exact destructive confirmation phrases, diagnostic/report schemas, and dynamic evidence remain byte-stable and untranslated.
- These presentation changes do not alter device/image identities, widget sensitivity, signal wiring, destructive confirmation, privilege separation, cancellation, verification, synchronization, or reports.

## Remaining Stage 4 scope

- Broader dialog and dynamic status/diagnostic catalog migration, plural review, and complete translation-aware accessibility review.
- Remaining portable distribution and filesystem work admitted by the pinned parity audit.
- UDF formatting remains excluded until a Linux-native post-format checker satisfies the formatter's read-only verification contract.
- ReFS remains non-portable without a verified Linux-native formatter.
- Windows To Go remains deferred.

All feature PRs remain gated on exact-head Go 1.22, native ARM64, static/vulnerability, privileged-loop, package, reproducibility, UEFI, FreeDOS, and formatter qualification workflows.
