# Roadmap

## 0.1 — safe raw writer (completed)

- Whole-disk enumeration
- Root-disk, partition, and read-only-target refusal
- Unmount, raw write, sync, and full verification
- Linux ARM64 static helper build

## 0.2 — graphical Ubuntu ARM64 application (completed)

- GTK desktop interface
- Installable ARM64 `.deb`
- Polkit privilege separation
- Standard Windows UEFI ISO preparation
- GPT/FAT32 creation and WIM splitting
- Windows and raw-image verification
- CI package artifact

## 0.3 — hardware qualification

- Surface Pro 11 X1E USB creation and boot tests
- Additional Snapdragon X Elite systems
- Multiple USB flash-drive controllers and capacities
- Recovery and failure-injection tests

## 0.4 — broader image support

- Streaming `.xz`, `.gz`, and `.zst` images
- Linux persistence partition creation
- Bad-block testing
- Downloaded-image checksum catalogue support

## 1.0 — supportable stable release

- Signed release artifacts
- Reproducible-build documentation
- Hardware compatibility matrix
- Independent security review of privileged operations
