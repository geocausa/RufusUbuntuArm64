# RufusArm64 0.15.0 development notes

Status: Stage 4 development branch; not a published release.

## Completed software tranches

- Guarded ext2 and ext3 data-only formatting through the existing GPT/MBR planner, exact identity binding, exact `FORMAT` confirmation, e2fsprogs creation, forced read-only `e2fsck -f -n`, exact filesystem/geometry/label readback, GTK integration, and real loop-device qualification.
- Application-scoped GTK appearance selection with canonical **System**, **Light**, and **Dark** modes.
- Complete main-window option and primary-action tooltips, applied after every composed integration while preserving more specific existing disclosures.
- A bounded GNU gettext runtime and deterministic `po/rufusarm64.pot` source catalog for primary-window headings, labels, actions, appearance wording, main-control tooltips, and related accessibility metadata.
- Static opening-state localization for the guarded data-only formatter and FreeDOS dialogs, including titles, headings, controls, placeholders, progress text, and initial report text.
- Static opening-state localization for the unprivileged read-only image checksum dialog while preserving the selected path, calculated digests, reports, and helper workflow.
- Static opening-state localization for destructive USB qualification while preserving profile IDs, target identity, generated erase confirmation, plans, JSON evidence, and execution.
- Static opening-state localization for read-only drive-image backup while preserving source/destination binding, generated SAVE confirmation, progress accounting, reports, publication, and process ownership.
- Static opening-state localization for authenticated experimental FFU review/restore while preserving trust inputs, source/target binding, exact confirmation, evidence, cancellation, and verification.
- Presentation-only localization for drive-backup format labels and Save-dialog chrome while preserving canonical format IDs, extensions, destination paths, planning, publication, and verification.
- Static-shell localization for Windows Setup options while preserving capability gating, prior selections, regional values, generated answer-file semantics, and writer contracts.
- Static opening-shell localization for verified image acquisition while preserving threshold trust, rollback protection, catalog/image evidence, resumable download state, and atomic publication.
- Static opening-shell localization for the dedicated persistent live USB wizard while preserving source/target identity, selected values, planning, confirmation, privileged creation, cancellation, qualification, and evidence.
- Translation-aware primary accessibility reconciliation with an exact reviewed inventory for mnemonics, assistive names/descriptions, icon-only controls, and non-destructive shortcuts.

## Appearance, tooltip, and localization contract

- **System** is the default and restores the GTK light/dark preference observed when RufusArm64 started.
- **Light** and **Dark** affect only the current RufusArm64 process and its dialogs.
- The canonical setting is stored in the existing owner-private settings JSON as `appearance: system|light|dark`.
- Missing, malformed, and unknown values resolve to **System**.
- The selector is exposed from the main header bar with tooltips and assistive-technology metadata.
- Every main image, target, persistence, Windows-layout, diagnostics, appearance, and primary action control has a bounded purpose/safety tooltip.
- Tooltip completion runs only after the complete composed window exists and never replaces a more specific tooltip supplied by an individual workflow.
- Localization loads the standard `rufusarm64` gettext domain and safely keeps the reviewed English source text when no valid catalog exists.
- Translation runs only after reviewed GTK construction has completed, and only exact admitted static messages are eligible.
- The guarded formatter and FreeDOS dialog classes are wrapped centrally after import; their original constructors, signal paths, identity binding, and execution code remain unchanged.
- Generated `FORMAT ...`, `WRITE FREEDOS ...`, `SAVE ...`, `RESTORE AUTHENTICATED FFU ...`, and persistence confirmation phrases, comparison logic, selected values, persistence size/label/runtime-validation values, plan keys, media capability summaries/reasons, local usernames, locale/time-zone identifiers, generated answer-file values, acquisition channel/mode/image IDs, trust paths, metadata versions/expiry/key IDs, filenames, sizes, digests, resumable state, machine-readable JSON, command flags, paths, identities, filesystem planner values, diagnostic/qualification/report schemas, and dynamic evidence remain byte-stable and untranslated.
- These presentation changes do not alter device/image identities, widget sensitivity, signal wiring, destructive confirmation, privilege separation, cancellation, verification, synchronization, or reports.

## Remaining Stage 4 scope

- Broader secondary-dialog and dynamic status/diagnostic catalog migration, plural review, completed language packs, and secondary-dialog translation-aware accessibility expansion.
- Remaining portable distribution and filesystem work admitted by the pinned parity audit.
- UDF formatting remains excluded until a Linux-native post-format checker satisfies the formatter's read-only verification contract.
- ReFS remains non-portable without a verified Linux-native formatter.
- Windows To Go remains deferred.

All feature PRs remain gated on exact-head Go 1.22, native ARM64, static/vulnerability, privileged-loop, package, reproducibility, UEFI, FreeDOS, and formatter qualification workflows.
