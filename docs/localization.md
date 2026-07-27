# RufusArm64 localization

RufusArm64 uses the standard GNU gettext domain `rufusarm64` for a bounded set of reviewed GTK interface text.

## Runtime catalog location

A compiled language catalog uses the normal system path:

```text
/usr/share/locale/LANGUAGE/LC_MESSAGES/rufusarm64.mo
```

Python's gettext runtime follows the process locale and standard environment variables such as `LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, and `LANG`. When no matching catalog is installed, the catalog is malformed, or a source string is not admitted to the current translation set, RufusArm64 keeps its reviewed English source text.

The loader opens each discovered GNU catalog directly instead of reusing Python gettext's process-global translation cache. This keeps repeated validation deterministic and prevents an earlier valid load from masking a later malformed catalog at the same path.

The project currently ships the translation source template rather than claiming completed language coverage:

```text
po/rufusarm64.pot
```

The Debian package installs that template as documentation at:

```text
/usr/share/doc/rufusarm64/rufusarm64.pot
```

## Updating the template

Reviewed strings are explicitly marked in `gui/rufusarm64_i18n.py`. Regenerate and verify the deterministic template with:

```bash
python3 scripts/update-pot.py
python3 scripts/update-pot.py --check
```

The generator deliberately omits timestamps, absolute paths, host facts, and line-number-dependent references so clean builds produce the same bytes.

## Current interface coverage

The runtime translates reviewed static main-window headings, labels, primary actions, appearance wording, main-control tooltips, and related accessibility names/descriptions after the composed window exists.

It also wraps the already-imported guarded data-only formatter and FreeDOS dialog classes centrally. After each original constructor has completed, one deferred exact-match pass covers the opening dialog title, heading, static explanatory and warning labels, control labels, entry placeholders, initial progress text, and initial empty-report text. The dialog modules themselves do not import localization code, so their operation and confirmation paths remain unchanged.

The same centralized wrapper covers the read-only image checksum dialog's static opening shell. The selected image path, calculated digest values, generated report, helper errors, clipboard content, and dynamic running/completion status remain untranslated.

The destructive USB qualification dialog is limited to static opening-shell text. Canonical `quick` and `full` profile IDs, their current combo presentation labels, the selected target and identity, generated `ERASE <device>` text, exact comparison, plans, JSON reports, diagnostics, save paths, and dynamic status remain untranslated.

The read-only drive-image backup dialog follows the same static-shell boundary. Source and destination paths, remembered directories, generated `SAVE ...` text, exact comparison, plans, byte totals, progress evidence, JSON reports, diagnostics, ownership/type/size checks, no-replace publication, process-group cancellation, parent-window logs, and dynamic status remain untranslated.

The authenticated experimental FFU dialog is limited to its static opening shell. Warning markup, image/target summary, trust and policy paths, file-chooser text, generated `RESTORE AUTHENTICATED FFU ...` confirmation, exact comparison, immutable review evidence, restore reports, diagnostics, dynamic status, cancellation evidence, and final safety messages remain untranslated.

Drive-backup format presentation translates only the visible Image format heading, labels, selector tooltip, and Save-dialog chrome. Canonical IDs (`raw`, `vhd`, `vhdx`, `iso`), extensions, selected IDs, generated filenames, destination paths, plans, reports, confirmation values, and operation evidence remain untranslated.

## Translator contract

- Translate the meaning of the complete source message; do not add new behavior or promises.
- Preserve a single mnemonic underscore in labels such as `_Create USB` and `_USB drive`.
- Preserve the exact `{shortcut}` placeholder in `Keyboard: {shortcut}`.
- Do not add Pango markup. RufusArm64 escapes translated text before restoring reviewed heading markup.
- Keep filesystem and platform names such as FAT32, NTFS, UEFI, ARM64, GPT, and MBR recognizable.
- Do not translate examples into instructions that imply boot, Secure Boot, hardware, or vendor compatibility beyond the English source claim.
- Wording that describes an exact confirmation phrase may be translated, but generated `FORMAT ...`, `WRITE FREEDOS ...`, `SAVE ...`, and `RESTORE AUTHENTICATED FFU ...` values themselves must never be added to a catalog.

## Safety boundary

The following remain byte-stable and outside the translation catalog:

- machine-readable JSON keys and report schemas;
- command-line flags and helper protocols;
- source or target device paths and identity tokens;
- filesystem identifiers used by planners and reports;
- generated destructive confirmation phrases and comparison logic;
- selected volume-label values and generated plan/report summaries;
- diagnostic field names and privileged-helper errors;
- dynamic operation status, progress evidence, and completion records.

Consequently, localization cannot change selected values, widget sensitivity, signal wiring, identity binding, privilege separation, confirmation matching, cancellation, execution, synchronization, verification, or report parsing.

Broader secondary-dialog migration, dynamic status/diagnostic localization, plural review, completed language packs, and complete translation-aware accessibility review remain later Stage 4 work.
