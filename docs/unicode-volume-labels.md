# Filesystem-specific Unicode volume labels

This tranche replaces duplicated label rules with one Linux-native contract across Windows media, Linux ISO Image mode, and the non-bootable formatter.

Qualified scope:

- FAT32 remains conservative: uppercase ASCII, no invisible trimming, and at most 11 on-disk bytes.
- NTFS preserves the user's exact Unicode and case, rejects controls and Windows-forbidden label characters, and enforces at most 32 UTF-16 code units.
- Empty labels use the existing `RUFUSARM64` default where bootable-media callers require one; explicit non-bootable empty labels remain empty.
- GTK mirrors the same UTF-16 accounting and character policy.
- Unit and real-loop tests bind requested, planned, formatted, reopened, and reported labels.

No Unicode normalization form is imposed: the exact valid input sequence is preserved so confirmation and readback evidence remain byte-for-byte explainable.
