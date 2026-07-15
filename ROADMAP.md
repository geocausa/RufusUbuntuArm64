# Roadmap

## 0.1 — safe raw writer (completed)

- Whole-disk enumeration
- System-disk refusal
- Raw write, sync, and verification

## 0.2 — graphical Ubuntu ARM64 application (completed)

- GTK interface and `.deb` package
- Polkit privilege separation
- Windows UEFI ISO preparation

## 0.3 — full code-hardening pass (completed)

- Device-identity binding and repeated destructive-command checks
- Reliable GUI cancellation and active-write close protection
- Strict image recognition and stronger MBR/GPT inspection
- Prevalidated WIM splitting and post-copy verification
- Cache-flushed verification and FAT32 filesystem checking

## 0.4 — Windows experience and usability (completed)

- Resizable, scrollable interface with remembered window size
- Detected layout display and editable volume label
- Windows Setup customization dialog and validated answer-file generation
- Early USB-capacity rejection and faster WIM preparation
- Compact WIM progress reporting
- Direct partition detection without a global udev-queue dependency
- Verified bundled AArch64 WIM engine with system fallback

## 0.5 — hardware qualification

- Surface Pro 11 X1E Windows and Linux USB boot tests
- Additional Snapdragon X Elite systems
- Multiple USB controllers, flash sizes, and failure-injection tests

## 0.6 — broader image support

- Streaming `.xz`, `.gz`, and `.zst` images
- Linux persistence partition creation
- Bad-block testing

## 1.0 — supportable stable release

- Signed release artifacts
- Reproducible-build documentation
- Hardware compatibility matrix
- Independent review of privileged operations
