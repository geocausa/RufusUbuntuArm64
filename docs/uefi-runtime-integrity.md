# UEFI runtime media integrity

Rufus upstream's **Enable runtime UEFI media validation** option installs [uefi-md5sum](https://github.com/pbatard/uefi-md5sum), which verifies a root `md5sum.txt` at boot and then chainloads the original removable-media fallback loader. This differs from RufusArm64's read-only UEFI structural and Secure Boot analyzer.

## Foundation implemented in 0.11 development

The `internal/runtimeintegrity` package generates, parses, and verifies the strict interoperable subset of `md5sum.txt` used by uefi-md5sum. It uses descriptor-rooted, no-symlink traversal, stable inode/type/size/time checks, deterministic `./path` ordering, lowercase MD5 records, and the `md5sum_totalbytes` progress extension. Verification reports changed, missing, unexpected, and total-byte mismatches.

The parser and generator retain upstream's published safety ceilings: a 64 MiB manifest, 100,000 records, and 512-byte paths. MD5 is used only because it is the on-media interoperability contract; RufusArm64 continues to use SHA-256 for download, source-identity, and destructive-write assurance.

## Not yet enabled

This foundation does not rename or replace a fallback loader. Bootloader source pinning and reproducible ARM64 builds, transactional installation and rollback, GUI integration, QEMU chainload tests, and physical Secure Boot qualification remain separate reviewed gates.
