## Summary

<!-- What changes, and why? -->

## Safety boundary

<!-- Describe source/target identity, confirmation, privilege, cancellation, changed-media reporting, flush/finalisation, and verification effects. Write “unchanged” only after checking each boundary. -->

## Upstream Rufus parity and work scope

- Corresponding upstream Rufus operation/default:
- Reviewed upstream commit/path:
- Complete source passes:
- Target bytes written and scaling basis:
- Target bytes read back and scaling basis:
- Maximum temporary storage and scaling basis:
- Default verification:
- Optional or separate qualification:
- Intentional Linux divergence and reason:

## Validation

<!-- Exact tests, workflows, hardware, and architecture evidence. -->

- [ ] Ordinary creation does not read or write unused target capacity by default.
- [ ] Every extra complete pass protects a named property that cannot be obtained more cheaply.
- [ ] `docs/operation-cost-contract.json` was reviewed and updated when work scope changed.
- [ ] User-facing progress and verification claims match the actual byte scope.
