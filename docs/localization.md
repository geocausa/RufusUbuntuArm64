# RufusArm64 localization

RufusArm64 uses the standard GNU gettext domain `rufusarm64` for its bounded primary GTK interface.

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

Primary-shell strings are explicitly marked in `gui/rufusarm64_i18n.py`. Regenerate and verify the deterministic template with:

```bash
python3 scripts/update-pot.py
python3 scripts/update-pot.py --check
```

The generator deliberately omits timestamps, absolute paths, host facts, and line-number-dependent references so clean builds produce the same bytes.

## Translator contract

- Translate the meaning of the complete source message; do not add new behavior or promises.
- Preserve a single mnemonic underscore in labels such as `_Create USB` and `_USB drive`.
- Preserve the exact `{shortcut}` placeholder in `Keyboard: {shortcut}`.
- Do not add Pango markup. RufusArm64 escapes translated text before restoring reviewed heading markup.
- Keep filesystem and platform names such as FAT32, NTFS, UEFI, ARM64, GPT, and MBR recognizable.
- Do not translate examples into instructions that imply boot, Secure Boot, hardware, or vendor compatibility beyond the English source claim.

## Safety boundary

This first localization tranche covers reviewed static primary-window headings, labels, primary actions, appearance wording, main-control tooltips, and related accessibility names/descriptions. Translation is applied only after the composed GTK window and its tooltip completion pass exist.

The following remain byte-stable and outside the translation catalog:

- machine-readable JSON keys and report schemas;
- command-line flags and helper protocols;
- source or target device paths and identity tokens;
- filesystem identifiers used by planners and reports;
- exact destructive confirmation phrases;
- diagnostic field names and privileged-helper errors;
- dynamic operation status and evidence records.

Consequently, localization cannot change selected values, widget sensitivity, signal wiring, identity binding, privilege separation, confirmation matching, cancellation, execution, synchronization, verification, or report parsing.

Broader dialog migration, dynamic status/diagnostic localization, plural review, and complete translation-aware accessibility review remain later Stage 4 work.
