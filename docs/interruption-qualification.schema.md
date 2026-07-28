# Interruption qualification matrix schema

`interruption-qualification.json` uses schema version 1.

Top-level fields:

- `schema_version`: exact integer schema identifier;
- `title`: human-readable inventory title;
- `required_boundaries`: stable boundary identifiers that may not disappear silently;
- `entries`: executable or explicitly physical-only qualification rows;
- `residual_software_gaps`: admitted software boundaries that still need executable coverage.

An automated entry must provide a repository-relative Go `_test.go` path, an exact `Test...` function, at least one execution platform, and a conservative invariant. A physical-only entry must use `phase` and `status` equal to `physical-only` and must not claim an executable test.

A residual software gap must identify its boundary, component, failure mode, why existing coverage is insufficient, and the planned test seam. Every required boundary must appear in an entry or residual gap. IDs are unique across both collections.

The executable checker in `internal/qualification/interruption_matrix_test.go` is the normative validator. This document is descriptive and must not be used to weaken its fail-closed rules.
