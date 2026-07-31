# Roadmap

## Qualification language

- **Software completed** means the exact source tree passed the repository's unit, integration, privileged-loop, native ARM64, package, and reproducibility gates.
- **Physical qualification pending** means firmware boot, Secure Boot acceptance, controller behavior, or other hardware evidence is still unrecorded for the current immutable candidate.
- A bounded Linux-native subset is not described as full Windows Rufus parity when material upstream media, firmware, or workflow breadth remains missing.

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

## 0.5 — hardware qualification (in progress)

- Surface Pro 11 X1E Windows and Linux USB boot tests
- Additional Snapdragon X Elite systems
- Multiple USB controllers, flash sizes, and failure-injection tests
- Immutable `0.15.0-rc2` Automatic/FAT32/NTFS and DD Image mode matrix tracked in issue #410

## 0.6 — Windows filesystem and firmware compatibility (software completed)

- Manual Automatic/FAT32/NTFS selection
- Verified ARM32, ARM64, IA32, RISC-V64, and x64 UEFI:NTFS boot partition with exact embedded loader manifest
- Optional Windows driver-folder staging
- FAT32 and NTFS post-write checks
- Windows CA 2023, SkuSiPolicy, and guarded UEFI FAT32/NTFS silent installation are software-complete; broader physical Windows Setup and firmware qualification remain bounded gaps

## 0.7 — Windows BIOS and driver integration (software completed)

- True x86/x86-64 Windows BIOS/CSM MBR and PBR support
- Secure driver-folder traversal and Windows PE driver auto-loading
- Source hashing and pinned legacy boot assets

## 0.8 — compressed, virtual-disk, and DBX support (software completed)

- ZIP, gzip, bzip2, XZ, LZMA, and Zstandard image preparation
- VHD, VHDX, QCOW2, and VMDK conversion with backing/encryption refusal
- Microsoft DBX cache updates and EFI direct-hash/certificate checks
- Target-sized preparation limits and compressed-image previews

## 0.9 — parity and product-quality programme (in progress)

- Rich progress and exportable diagnostics (software completed)
- Strict local signed catalog, threshold-root built-in channel, rollback-protected metadata cache, graphical acquisition workflow, source-only offline public-metadata administration, and signed release asset-graph enforcement (software implemented; production offline-key ceremony and public metadata publication pending)
- Linux persistence planner, verified writable-tree copy, guarded GPT/UEFI creator, dedicated identity-bound graphical wizard, and checksum-backed reboot qualification reports (bounded Ubuntu casper and Debian live-boot subset; broader distribution and physical qualification pending)
- FreeDOS creation (software completed in 0.13)
- Experimental Windows To Go software path completed for Windows 11 client ARM64 GPT/UEFI/NTFS, including live direct-NTFS WIM progress, exact-target kernel I/O-failure cancellation, mandatory internal-disk isolation, and hash-bound Rufus-style first-boot customizations; physical firmware boot and first-boot qualification remain pending
- Production offline-root provisioning, published signed catalog, and mirror operations
- Broader distribution-specific boot compatibility workarounds beyond structural reporting
- Rufus 4.15 audit remediation tracked in issue #412

## 0.11 — UEFI analysis and runtime media integrity (software completed; physical qualification pending)

- Descriptor-rooted fallback-loader, PE/COFF, DBX, SBAT, and firmware-policy analysis with CLI and GTK reporting
- Rufus-compatible `md5sum.txt` generation, parsing, and full-tree verification
- Reproducibly built, source-retained ARM64 `uefi-md5sum` loader with transactional installation and rollback
- Guarded persistent-writer and GUI integration with explicit unsigned disclosure and unsupported-mode refusal
- Pinned AArch64 QEMU success, corruption, and original-loader chainload qualification
- The optional loader remains unsigned; Secure Boot acceptance and physical Surface Pro 11 coverage are not established

## 0.12 — Stage 1 guarded backup and product completion (software completed)

- Identity-bound command and GTK workflow for read-only removable-drive image capture
- Exact destination planning and confirmation, progress, cancellation, SHA-256, atomic publication, and desktop ownership
- Focused privilege, process-lifecycle, report-schema, launcher-isolation, native ARM64, and reproducible-package audit
- Clean Stage 1 release package and rollback documentation; physical play-testing continues as field feedback

## 0.13 — Stage 2 practical Rufus parity (software completed for stated scope)

- Guarded data-only restore/format workflow and deterministic FreeDOS 1.4 media creation
- Explicit post-operation recreate and ordinary-storage restoration paths
- Bounded Linux hybrid/optical compatibility reporting with El Torito and bootloader fingerprints
- Resumable verified graphical acquisition over the existing signed-catalog trust core
- GTK keyboard navigation, assistive-technology naming, and selectable status details
- Windows multi-edition WIM/ESD/split-SWM capability and payload disclosure
- Release-candidate package, rollback notes, and human real-machine checklist; broader hardware sanity remains a separate qualification boundary

## 0.14 — Stage 3 advanced imaging and recovery (software completed for stated scope)

- Descriptor-bound raw, dynamic VHD, dynamic VHDX, and mounted-filesystem ISO/UDF drive backup
- Experimental authenticated single-store-v1 FFU restore with strict trust, target, confirmation, write-order, and complete-verification gates
- Reusable identity-bound USB qualification reports and bounded compressed-image preparation progress
- El Torito UEFI extraction and opt-in Windows 11 setup Quality of Life policy
- Privileged loop qualification, native ARM64 execution, Go 1.22 compatibility, static/vulnerability audit, and reproducible Debian packaging
- FFU capture and production physical FFU support remain unimplemented or unqualified

## 0.15 — ISO Image mode parity tranche (completed)

- Software implementation is complete for the bounded tranche; physical firmware qualification remains pending.
- Rufus-style ISO Image mode versus DD Image mode choice for suitable ARM64 UEFI Linux ISOHybrid media
- ISO Image mode selected as the recommended default, with explicit immutable exact-clone DD fallback
- Automatic, FAT32, or NTFS selection; Automatic prefers FAT32 and selects NTFS only when complete-tree inspection requires it
- Reviewed MBR or GPT layout, 4/8/16/32 KiB clusters, filesystem-specific labels, and exact option binding through confirmation, privileged helper, diagnostics, and result evidence
- Shared pinned Rufus 4.15 UEFI:NTFS asset admission, exact five-architecture embedded-loader manifest, layout planning, writing, and complete readback for Windows and Linux NTFS media
- Complete copied-file SHA-256 verification, filesystem checking, target flushing, primary/backup GPT readback, and detached/reopened MBR/GPT FAT32/NTFS loop qualification
- Immutable `0.15.0-rc2` candidate published for the focused physical ARM64 matrix in issue #410
- BIOS/CSM or dual-mode Linux extraction, NTFS persistence, broader distribution adaptations, and universal firmware claims remain outside this tranche

## 0.16 — consolidated community release (completed)

- Publishes the complete post-0.15 source line as one exact tagged ARM64 package.
- Includes guarded Windows installation and Windows To Go paths, UEFI:NTFS architecture validation, Linux ISO Image mode improvements, advanced imaging utilities, and the safety/readback model documented in this repository.
- Community release status means the exact software gates passed; it does not claim exhaustive physical testing across all images, firmware, controllers, machines, or architectures.
- Future defects should be reported as focused GitHub issues with non-sensitive diagnostics and exact media/hardware details.

## 1.0 — supportable stable release

- Signed release artifacts
- Reproducible-build documentation
- Hardware compatibility matrix
- Independent review of privileged operations
- Production update and official-image trust operations
- Translation catalog and translation-aware accessibility review
