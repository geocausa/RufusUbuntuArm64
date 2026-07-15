# Changelog

## 0.2.0 — 2026-07-15

- Added a GTK desktop application designed for non-technical Ubuntu users.
- Added an installable ARM64 Debian package and application-menu launcher.
- Added Polkit-based administrator authentication for destructive operations.
- Added automatic handling for Linux ISOHybrid/raw images and Windows UEFI installation ISOs.
- Added GPT/FAT32 Windows USB creation and automatic WIM/ESD splitting.
- Added Windows ISO architecture detection and capacity checks before erasing the target.
- Added optional SHA-256 verification for raw images and copied Windows setup files.
- Added stronger writer locking, cancellation cleanup, fixed-disk filtering, and system-disk refusal.
- Added ARM64 package, Python syntax, Go race, unit-test, formatting, and vet checks in CI.

## 0.1.0 — 2026-07-15

- Initial safe raw-image writer.
