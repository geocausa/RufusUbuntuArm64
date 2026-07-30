# Filesystem-specific Unicode volume labels

This tranche replaces duplicated label rules with one Linux-native contract across Windows media, Linux ISO Image mode, and the non-bootable formatter.

Qualified scope:

- FAT32 remains conservative: uppercase portable ASCII, no invisible trimming, and at most 11 on-disk bytes.
- NTFS preserves the user's exact Unicode, case, and valid punctuation and enforces at most 32 UTF-16 code units.
- NTFS volume labels are not filenames. Characters such as `*`, `?`, `:`, `/`, `\`, `|`, `<`, `>`, and `"` are therefore preserved rather than incorrectly rejected as filename-reserved characters.
- UDF 2.01 preserves exact valid Basic Multilingual Plane text through OSTA compressed Unicode: up to 126 Latin-1 characters or 63 characters when 16-bit encoding is required. Non-BMP input is refused because the supported `udftools` path cannot round-trip it safely.
- Leading or trailing whitespace, control characters, invalid UTF-8, and over-limit surrogate-pair input fail before destruction so confirmation and logs remain unambiguous.
- Empty labels use the existing `RUFUSARM64` default where bootable-media callers require one; explicit non-bootable empty labels remain empty.
- Automatic filesystem mode first applies the FAT32 canonical form when possible; otherwise it carries an exact NTFS-capable label until the helper resolves the image filesystem.
- GTK mirrors the same UTF-16 accounting and character policy.
- Unit and real-loop tests bind requested, planned, formatted, reopened, and reported labels, including mixed case, non-ASCII text, UDF OSTA boundaries, surrogate pairs where supported, and valid NTFS punctuation.

No Unicode normalization form is imposed: the exact valid input sequence is preserved so confirmation and readback evidence remain byte-for-byte explainable.
