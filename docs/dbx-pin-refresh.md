# Microsoft DBX pin review and refresh

RufusArm64 does not download the Microsoft Secure Boot revocation database from a moving branch. Online DBX acquisition is bound to one reviewed commit in Microsoft's public `secureboot_objects` repository and to the exact Git blob identity of each supported architecture file.

## Current reviewed objects

Repository commit:

```text
06fe58a31d2da381fb68c6d9f30af0dfb91cbe3a
```

| Architecture | Git blob SHA-1 |
| --- | --- |
| x86 | `142584cbd3ac2045aa6936e3c5e1814fc8b28149` |
| amd64 | `f6ccec74a078267d56222b44d31ad30757ee8717` |
| arm | `feb134b01b59c0d95730466ca75a31d326848c99` |
| arm64 | `33520068f2602fbd2c739b7f71e8946f5ba6ccd4` |

Microsoft does not publish an IA-64 DBX object at this reviewed commit. The online updater therefore refuses `ia64` instead of constructing a URL that cannot be reviewed or fetched.

Git blob SHA-1 is used here only because it is the object identifier of the reviewed file in this Git repository. It is not treated as a modern general-purpose cryptographic signature. The trust decision is the reviewed immutable commit-and-blob pair. The parser's `authenticated_update_format` field means that the file has the expected UEFI authenticated-variable update structure; RufusArm64 does not independently validate the embedded PKCS#7 signer chain.

## Refresh ceremony

A pin refresh must be a dedicated reviewed pull request. It must not be combined with unrelated feature or release work.

1. Select an exact commit from the official `microsoft/secureboot_objects` repository. Never use `main`, a tag that can move, a redirector, or an unqualified download URL.
2. Review the selected commit and the intervening diff. Confirm that the intended `PostSignedObjects/DBX/<architecture>/DBXUpdate.bin` files are ordinary repository blobs and that no path has been replaced by a link or generated redirect.
3. Download each file from a commit-qualified raw URL and record its byte length, SHA-256, Git blob SHA-1, authenticated-update timestamp, signature-list count, hash count, and certificate count.
4. Recompute the Git object identity from the exact bytes. Git hashes the object header and contents together:

   ```sh
   file=DBXUpdate.bin
   size=$(wc -c <"$file")
   { printf 'blob %s\0' "$size"; cat "$file"; } | sha1sum
   ```

   The result must match `git ls-tree <commit> -- PostSignedObjects/DBX/<architecture>/DBXUpdate.bin` and the repository contents API blob SHA.
5. Inspect every file with the RufusArm64 DBX parser. Require a valid authenticated-update structure and at least one EFI signature. This is structural validation only; do not describe it as independent signer verification.
6. Update `microsoftDBXRepositoryCommit` and the architecture blob table in `internal/secureboot/dbx_online.go` together. Remove an architecture if the exact object is absent; never retain an old blob under a new commit without explicitly reviewing that decision.
7. Update the exact-pin tests and this document in the same pull request. Tests must prove that moving-branch URLs, malformed object IDs, architecture/path mismatches, and byte changes are rejected before any cache destination is created or replaced.
8. Run all exact-head CI gates, including Go 1.22, native ARM64 execution, static and vulnerability checks, UEFI validation, privileged loop invariants, and reproducible package verification.
9. Record the reviewed Microsoft commit, all blob IDs, parser summary, CI run, reviewer, and date in the pull request. Merge only after the evidence is complete.

## Cache and rollback behavior

The downloaded bytes are checked against the pinned Git blob identity before parsing and before the cache directory or destination is created. Publication uses an owner-private temporary file and atomic rename. A failed download, pin mismatch, malformed update, or interrupted write leaves the previously published cache file untouched.

Rolling back the application also rolls back the reviewed pin table. Cached files remain self-describing through their SHA-256 and the updater's repository-commit and Git-blob provenance fields; callers should retain those fields in diagnostics when investigating a DBX change.
