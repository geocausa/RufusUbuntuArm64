# Rufus Linux ARM64 MVP

An **experimental, unofficial** Linux ARM64 boot-media writer inspired by the safe raw-image workflow of Rufus.

This is not an official Rufus release and it is not yet a feature-complete port. Version 0.1 focuses on a narrow, auditable core:

- List removable USB/MMC whole disks using `lsblk`
- Refuse partitions, read-only devices, and the running root disk
- Refuse fixed disks unless `--allow-fixed` is explicitly supplied
- Show mounted child filesystems and unmount them before writing
- Stream `.img` and ISOHybrid images to a raw block device
- Refuse plain optical ISOs without disk signatures unless `--force-raw` is explicit
- Flush writes before reporting success
- Optionally compare every written byte and report SHA-256
- Build a static Linux ARM64 binary with Go

## Destructive-operation warning

Writing an image erases the selected target. Review the device path, capacity, model, and transport every time. The software includes safety checks, but no safety mechanism can compensate for selecting the wrong disk.

## Build on Linux ARM64

```bash
go build -trimpath -ldflags="-s -w" -o rufus-linux ./cmd/rufus-linux
```

## Cross-compile from Linux x86-64

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" -o dist/rufus-linux-arm64 ./cmd/rufus-linux
```

## Install a release binary

```bash
tar -xzf rufus-linux-arm64-v0.1.0-linux-arm64.tar.gz
cd rufus-linux-arm64-v0.1.0-linux-arm64
sudo ./install.sh ./rufus-linux-arm64
```

## Usage

```bash
./rufus-linux list
sudo ./rufus-linux write --image ubuntu.iso --device /dev/sda --verify
```

For a fixed/non-removable target, the tool refuses to continue unless all other checks pass and `--allow-fixed` is provided:

```bash
sudo ./rufus-linux write --image image.img --device /dev/nvme1n1 --allow-fixed --verify
```

Use `--dry-run` to perform selection and size checks without opening the target for writing. Plain optical ISOs such as standard Windows installation media are refused because raw copying usually does not create Rufus-equivalent USB media; `--force-raw` exists only for deliberate expert use.

## Current scope and non-goals

Version 0.1 writes images that are already bootable as raw disk images or ISOHybrid media. It does **not** yet implement Rufus's extracted-ISO workflow, FAT32 creation, WIM splitting, Windows installation customizations, UEFI:NTFS, Windows To Go, persistence partition creation, bad-block testing, or a graphical interface.

See [ROADMAP.md](ROADMAP.md) for the staged plan and [CHANGELOG.md](CHANGELOG.md) for completed work.

## Runtime dependencies

- Linux
- `lsblk`, `findmnt`, `umount`, and `blockdev` from util-linux
- Root privileges for writing

The executable itself uses only the Go standard library and can be built with `CGO_ENABLED=0`.

## Validation status

Version 0.1.0 passes unit tests, the Go race detector, `go vet`, native CLI smoke tests, and Linux ARM64 cross-compilation. The generated executable is a statically linked AArch64 ELF. A physical USB write/boot test has not been performed in the build environment, so treat this as an engineering preview rather than production-proven media software.

## Relationship to Rufus

Rufus is a separate GPL-licensed project by Pete Batard and contributors. This repository is an independent Linux implementation and does not claim endorsement or official status. Any future incorporation of Rufus source code must preserve its GPL notices and corresponding-source obligations.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
