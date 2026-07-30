# Linux ISO compatibility corpus

This corpus turns Linux-image compatibility into versioned, reproducible evidence instead of an informal list of distributions that happened to be tried once.

The machine-readable contract is `docs/linux-iso-corpus.json`. The runner is `scripts/linux_iso_corpus.py`.

## Decisions

Each qualified artifact has exactly one reviewed result:

- `iso-image-candidate`: a plain, recognised optical image with a validated UEFI El Torito boot entry. Hybrid media may also offer DD mode when a coherent MBR/GPT disk layout is present; optical-only media offer ISO Image mode only. The privileged extraction planner must still pass every filename, filesystem, fallback-loader, capacity, identity and UEFI:NTFS check before erasure.
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

Pending official entries identify the next representative families without claiming that they pass. Once signed upstream checksum material is verified, a pending entry may bind the exact filename, byte size and SHA-256 before analyser qualification. Any local file using that filename must match those bytes before inspection, so an interrupted download cannot produce a compatibility decision. A pending image is never promoted to qualified until its exact analyser result is committed.

Compact synthetic fixtures are generated deterministically by the runner. They cover stable parser and refusal boundaries without storing opaque binaries in the repository.

## Current qualified evidence

The qualified official entries are Ubuntu 26.04 Desktop ARM64, Debian 13.6.0 ARM64 netinst and Fedora Everything 44 aarch64 netinst. Ubuntu's SHA-256 matches Ubuntu's published `SHA256SUMS`. Debian's detached `SHA256SUMS.sign` was accepted with `gpgv` and the Debian CD signing key. Fedora's signed checksum was accepted with the Fedora 44 primary key before its exact size and SHA-256 were admitted.

Ubuntu and Debian are hybrid GRUB media with validated UEFI El Torito entries. Fedora is optical-only UEFI/GRUB media with no coherent MBR/GPT raw USB layout. All three are `iso-image-candidate` artifacts; DD remains available only for the hybrid entries.

Ubuntu was written physically on one USB-attached Kingston SNS4151S316G target using MBR/UEFI/NTFS with a 4 KiB cluster size and the label `Rufus Ünicode 测试`. Complete copied-file verification, NTFS checking, exact label readback and UEFI:NTFS readback passed.

Debian was written to the same target using GPT/UEFI/FAT32 with a 4 KiB cluster size and label `DEBIAN136`. Primary and backup GPT validation, FAT checking, exact label readback, 1,217-file readback and the native ARM64 fallback loader check passed.

Fedora was written to the same target using MBR/UEFI/FAT32 with a 4 KiB cluster size and label `FEDORA44`. Complete copied-file SHA-256 verification, FAT checking, fallback-loader readback, the 978,661,376-byte installer image and detached read-only reopen passed. These records do not establish firmware boot or Secure Boot behavior.

The manifest tracks Linux Mint, Bazzite, Nobara, Nutanix and umbrelOS as pending representatives. The openSUSE representative is pinned to `openSUSE-Tumbleweed-DVD-aarch64-Snapshot20260714-Media.iso` instead of the rolling `Current` alias. Its detached checksum signature was accepted with the openSUSE Project Signing Key fingerprint `AD48 5664 E901 B867 051A B15F 35A2 F86E 29B7 00A4`; the complete 4,099,753,984-byte artifact matched the signed SHA-256 `be9ff4dae638029557f5cb9d8e1c55fcc50f9c8ad1253c3d2e401fffcc41f547`.

Exact analysis classifies this image as `dd-only`: it is a recognised hybrid ISO/raw layout with ISO9660 content and a BIOS El Torito entry, but no validated UEFI boot entry or supported extraction bootloader. RufusArm64 therefore preserves its embedded MBR, FAT32 boot partition, Linux partition and optical structures byte-for-byte rather than offering ISO Image extraction. The image was physically written to an identity-bound 31,914,983,424-byte removable USB target. The helper's complete physical-device verification and an independent SHA-256 readback both matched the signed source hash. This establishes exact write/readback behavior, not firmware boot, installation success or Secure Boot compatibility.

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
