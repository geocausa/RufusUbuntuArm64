# Linux ISO compatibility corpus

This corpus turns Linux-image compatibility into versioned, reproducible evidence instead of an informal list of distributions that happened to be tried once.

The machine-readable contract is `docs/linux-iso-corpus.json`. The runner is `scripts/linux_iso_corpus.py`.

## Decisions

Each qualified artifact has exactly one reviewed result:

- `iso-image-candidate`: a plain, recognised hybrid image with a validated UEFI El Torito boot entry. This permits the GUI to offer ISO Image mode, but the privileged extraction planner must still pass every filename, filesystem, fallback-loader, capacity, identity and UEFI:NTFS check before erasure.
- `dd-only`: recognised raw media that remains valid for exact byte-for-byte writing but is outside the reviewed extraction boundary.
- `refuse`: an input the automatic writer rejects, including malformed or arbitrary files and direct filesystem images that are not complete disk/ISOHybrid media.

A software decision does not prove firmware boot, installation success, Secure Boot compatibility or support on unrelated hardware.

## Evidence classes

Official images are not committed to Git. A qualified official entry binds:

- the exact upstream filename;
- byte size;
- SHA-256 digest;
- read-only helper inspection;
- the headless compatibility profile; and
- the expected decision.

Pending official entries identify the next representative families without claiming that they pass. A pending image is never promoted to qualified until its official checksum and exact analyser result are committed.

Compact synthetic fixtures are generated deterministically by the runner. They cover stable parser and refusal boundaries without storing opaque binaries in the repository.

## Current qualified evidence

The initial official entries are Ubuntu 26.04 Desktop ARM64 and Debian 13.6.0 ARM64 netinst. Ubuntu's SHA-256 matches Ubuntu's published `SHA256SUMS`. Debian's detached `SHA256SUMS.sign` was accepted with `gpgv` and the Debian CD signing key before its image checksum was admitted. Both images are classified as hybrid GRUB media with validated UEFI El Torito entries and therefore as `iso-image-candidate` artifacts.

Ubuntu was written physically on one USB-attached Kingston SNS4151S316G target using MBR/UEFI/NTFS with a 4 KiB cluster size and the label `Rufus Ünicode 测试`. Complete copied-file verification, NTFS checking, exact label readback and UEFI:NTFS readback passed.

Debian was then written to the same target using GPT/UEFI/FAT32 with a 4 KiB cluster size and label `DEBIAN136`. Primary and backup GPT validation, FAT checking, exact label readback, 1,217-file readback and the native ARM64 fallback loader check passed. Neither record establishes firmware boot.

The manifest tracks Linux Mint, Fedora, Bazzite, Nobara, openSUSE, Nutanix and umbrelOS as pending representatives.

## Run the corpus

Use a locally built or installed helper and one or more directories containing official images:

```bash
PYTHONPATH=gui python3 scripts/linux_iso_corpus.py \
  --image-dir "$HOME/Downloads" \
  --helper /usr/lib/rufusarm64/rufusarm64-helper \
  --allow-missing
```

`--allow-missing` applies only to entries explicitly marked `pending`. Missing qualified media is always a failure. Omit the option for a complete qualification run.

Emit a machine-readable report with:

```bash
PYTHONPATH=gui python3 scripts/linux_iso_corpus.py \
  --image-dir "$HOME/Downloads" \
  --helper /usr/lib/rufusarm64/rufusarm64-helper \
  --allow-missing \
  --json
```

Select one or more entries with repeated `--entry ID` arguments.

## Updating the corpus

For every new official image:

1. download only from the project's official distribution surface;
2. verify the project's signed checksum material when it is available;
3. record the exact filename, size and SHA-256;
4. run the read-only corpus analyser;
5. review the decision and compatibility profile;
6. run the appropriate loop and physical media qualification before claiming a write path; and
7. commit the immutable evidence while leaving the multi-gigabyte artifact outside Git.

Rolling distributions require a new corpus entry or corpus-version update when their artifact bytes change. Reusing an old expected result for a new digest is forbidden.
