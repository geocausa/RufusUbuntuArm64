# Physical FFU qualification record

This procedure closes the remaining Stage 3 evidence boundary for the currently supported experimental single-store-v1 full-flash FFU profile. It does not expand the parser or writer, enable fixed disks, add automatic unmounting, or claim that an arbitrary FFU will boot arbitrary hardware.

A passing record applies only to one exact source commit, package, authenticated vendor FFU, removable target, ARM64 host, target firmware configuration, and observed boot attempt.

## Safety boundary

Use only disposable physical removable hardware whose complete contents may be destroyed. Do not test on an internal disk, the running system disk, valuable media, or a target containing data that has not been independently backed up.

The record sealer in `scripts/ffu-physical-qualification.py` is non-privileged and performs no device access. It only:

- validates the complete review-to-execution JSON evidence through the production graphical result contract;
- binds the exact source commit, package hash, vendor-image hash and reviewed source size;
- binds the exact restored target identity and capacity;
- records the ARM64 host, physical target, firmware and Secure Boot state;
- requires hashed supporting evidence for every claimed boot attempt; and
- emits a deterministic qualification SHA-256 without replacing an existing output file.

It cannot prove that a photograph, serial log or human observation is truthful. The maintainer must preserve the original evidence bundle and sign off the release decision.

## Required inputs

Preserve these files before touching the target:

1. the exact release-candidate source commit;
2. the exact ARM64 Debian package and its SHA-256;
3. the signed vendor FFU, byte size, SHA-256 and publisher name;
4. the explicit trust store, trust-metadata policy and publisher policy used by the review;
5. the complete read-only review JSON; and
6. the complete privileged restore JSON.

The review and restore can be obtained from the experimental CLI or from the complete GTK diagnostic payloads. Do not reconstruct either payload from screenshots or summaries.

The restore result must remain byte-for-byte available. A process exit code, success dialog or partial log is not sufficient.

## Restore gate

Before firmware testing, the production result normalizer must accept the complete evidence chain and report `verified`:

- authenticated source and active trust generation;
- exact target plan and live target preflight;
- mandatory source lease;
- exclusive target session;
- exact destructive confirmation;
- one-shot mutation authorization;
- complete planned write accounting;
- synchronization; and
- complete readback verification.

A `not-started`, `partially-modified`, `written-unverified`, malformed, missing or uncorrelated result is a **NO-GO**. Never boot a target that may be partially modified or was written without complete readback verification.

## Physical observations

Record the real ARM64 host and target details independently of `/dev/...` naming:

- host model, Ubuntu release, kernel release and architecture;
- target make/model, serial number or laboratory asset tag, capacity and transport;
- intended boot-system model and firmware version;
- Secure Boot state: `enabled`, `disabled` or `unknown`;
- exact firmware boot entry selected;
- whether the tested media is the same physical target that produced the restore evidence;
- tester, ISO date and plain-language observations; and
- one or more SHA-256-addressed photos, firmware screenshots, serial-console captures or diagnostic logs for every attempted boot.

Keep serial numbers or sensitive images in a private evidence bundle when publication is inappropriate. The normalized result may be published only after reviewing its contents.

## Input record

Create a private JSON file with this envelope. Insert the complete unmodified review and restore objects in place of the placeholders.

```json
{
  "schema": 1,
  "mode": "ffu-physical-qualification",
  "source_commit": "40-lowercase-hex-commit",
  "package": {
    "filename": "rufusarm64_0.14.0~rc1_arm64.deb",
    "version": "0.14.0~rc1",
    "sha256": "64-lowercase-hex"
  },
  "vendor_image": {
    "filename": "vendor.ffu",
    "size_bytes": 123456789,
    "sha256": "64-lowercase-hex",
    "publisher": "Vendor name from the approved policy"
  },
  "review": {},
  "restore": {},
  "host": {
    "architecture": "aarch64",
    "os_release": "Ubuntu 24.04 LTS",
    "kernel_release": "kernel release",
    "model": "qualification host model"
  },
  "target": {
    "identity": "exact target identity from the review",
    "capacity_bytes": 123456789,
    "make_model": "physical target make and model",
    "serial_or_asset_tag": "private serial or laboratory tag",
    "transport": "USB"
  },
  "firmware": {
    "system_model": "boot-test system model",
    "firmware_version": "firmware version",
    "secure_boot": "unknown"
  },
  "boot": {
    "attempted": false,
    "booted": false,
    "same_restored_media": false,
    "tester": "maintainer name",
    "date": "2026-07-26",
    "firmware_entry": "Not attempted",
    "observations": "Restore evidence sealed before firmware testing."
  },
  "evidence": []
}
```

Seal the pre-boot record without elevation:

```bash
python3 scripts/ffu-physical-qualification.py \
  --record private-ffu-qualification.json \
  --output ffu-qualification-preboot.json \
  --summary
```

A verified software restoration with no boot attempt produces `pending-boot`, not a pass.

## Firmware boot validation

1. Shut down normally after the verified restore.
2. Identify the physical target by its recorded make/model and serial or asset tag, not only by the previous Linux device path.
3. Move that same target to the intended ARM64 system.
4. Record firmware version and Secure Boot state before selecting the boot entry.
5. Select the explicit entry and observe the earliest meaningful vendor operating-system or recovery environment screen.
6. Preserve a photo, firmware screenshot, serial-console log or equivalent evidence and calculate its SHA-256.
7. Update the private input record with `attempted: true`, the observed `booted` result, `same_restored_media: true` only after physical identity confirmation, the exact boot entry and evidence metadata.
8. Seal a new output file; never overwrite the pre-boot record.

A pass requires all of the following:

- the restore outcome is `verified`;
- a physical boot was attempted;
- the tested target is explicitly recorded as the same restored media;
- the intended firmware reached the recorded boot milestone; and
- at least one supporting evidence item has a valid SHA-256.

The normalized decision is one of:

- `qualified` — one exact configuration passed;
- `pending-boot` — software restoration passed but no physical boot was attempted;
- `no-go-restore` — the restore was not completely verified; or
- `no-go-boot` — a verified target did not pass the recorded boot attempt.

## Release decision

Do not change experimental or unsupported wording merely because the sealer emits `qualified`. The release maintainer must inspect the original vendor FFU provenance, policies, raw review and restore JSON, physical evidence, exact CI results and qualification SHA-256 at one release-candidate commit.

A supported release claim must remain bounded to the tested profile and must not imply support for staged-GPT FFUs, partial updates, validation-descriptor profiles, automatic unmounting, fixed/internal targets, other vendors, other firmware, other target geometry, or universal bootability.
