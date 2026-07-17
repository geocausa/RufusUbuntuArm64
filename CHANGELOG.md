# Changelog

## 0.10.4 — 2026-07-17

- Fixed persistence analysis for the official Ubuntu 26.04 ARM64 desktop ISO root alias `ubuntu -> .`.
- Omitted only direct root-self aliases that cannot be represented on FAT32 and would otherwise recursively duplicate the complete media tree.
- Kept nested links back to the media root, host-path escapes, absolute escapes, cycles, special nodes, and unbounded traversal strictly refused.
- Added regression coverage for analysis, verified copying, omission accounting, and preservation of the ordinary casper payload.
