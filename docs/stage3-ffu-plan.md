# Stage 3 FFU restoration plan

## Goal

Add safe, reviewable restoration of Microsoft Full Flash Update (`.ffu`) images on Ubuntu ARM64 without weakening the existing source/target identity, confirmation, cancellation, and verification boundaries.

## Delivery order

1. FFU inspection and feasibility gate.
2. Read-only metadata reporting and target compatibility checks.
3. Linux-native restore provider behind CLI-only experimental gating.
4. Deterministic plan/report contract, cancellation, and post-write verification.
5. GTK integration only after the provider is independently qualified.
6. Real-device evidence before a supported release claim.

## Non-goals for the first tranche

- Capturing or creating FFU images.
- Device-specific firmware flashing protocols.
- Bypassing FFU platform, sector-size, or target-capacity requirements.
- Treating file-extension recognition as proof of a valid FFU image.
- Windows To Go or arbitrary bootloader installation.

## Safety requirements

- Parse and validate the FFU security and image headers before authentication.
- Bind all metadata and payload reads to one stable source identity.
- Calculate the exact minimum destination size before erasure.
- Reject unsupported FFU variants and malformed chunk descriptors.
- Require the exact removable target identity and a mode-specific confirmation phrase.
- Never write outside the selected whole-device target.
- Report planned bytes, written bytes, verification scope, image identity, target identity, and final reusable/incomplete state.
- Cancellation after mutation must conservatively mark the destination changed and incomplete.
- Verification must be explicit about whether it covers all restored payload blocks or a narrower scope.

## Initial architecture finding

The existing imaging probe already recognizes FFU by the `SignedImage ` signature and classifies it as `InputFFU`, but deliberately reports it unsupported. This gives Stage 3 a clean entry point without changing ordinary raw, compressed, or virtual-disk behaviour.

## Release boundary

FFU support remains unsupported until a Linux-native provider, fixture corpus, privileged loop qualification, native ARM64 CI, malformed-input tests, cancellation tests, and real-device restoration record all pass at one exact release-candidate commit.
