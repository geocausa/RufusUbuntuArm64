# RufusArm64 0.15 accessibility review

This review covers the currently admitted static primary-window interface after every composed integration and gettext translation pass.

## Reviewed inventory

- Label mnemonics bind **Boot image** to the image chooser and **USB drive** to the removable-drive selector.
- Visible mnemonics cover verified download, checksums, Create USB, cancellation, read-only UEFI validation, data-only formatting, and FreeDOS entry points.
- Assistive names and descriptions cover source selection, target selection, refresh, verified acquisition, checksums, destructive qualification, creation, cancellation, UEFI validation, compatibility details, verification, progress, diagnostics, storage restoration, FreeDOS, post-operation actions, appearance, and About.
- Visible accelerators remain limited to non-destructive refresh, acquisition, checksum, UEFI-validation, and About actions. Create USB and cancellation have no direct accelerator.

Every reviewed static mnemonic, assistive name, and assistive description is an exact gettext catalog member. Real GNU `.mo` tests require visible text and assistive metadata to translate together.

## Preserved safety boundary

The accessibility layer does not change widget sensitivity, signal wiring, default responses, source or target identity, selected values, generated confirmation phrases, exact comparisons, helper commands, privilege separation, cancellation, synchronization, verification, reports, diagnostics, or operation evidence.

Paths, identities, plans, confirmation values, dynamic status, reports, diagnostics, and evidence remain outside translation and are not rewritten as assistive metadata. Secondary-dialog custom-metadata expansion remains separately reviewed work.
