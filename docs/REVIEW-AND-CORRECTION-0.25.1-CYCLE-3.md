# Review and Correction Cycle 3 — Foundation 0.25.1

## Scope

This cycle reviewed the newly introduced security-finding lifecycle before proceeding to the next operational coding increment.

## Defects found and corrected

1. Finding status changes allowed unrestricted transitions.
2. Concurrent administrators could overwrite a newer finding status.
3. Accepted-risk disposition did not require a separately delegated capability.
4. Status-change audit events attributed every finding to File 24 instead of the finding's native module.
5. Status changes did not require an accountability note.
6. The plugin boot called `Capabilities::registerHooks()` while that method was absent, creating a latent runtime fatal error not detected by syntax lint.
7. The new findings submenu did not load the Security Center stylesheet.
8. The findings table had no bounded horizontal overflow treatment on narrow screens.
9. Existing tests covered only simple creation and resolution, not stale writes, concurrency, transition policy or risk acceptance.

## Corrections

- Added an explicit status-transition matrix and controlled reopen path.
- Added optimistic concurrency using the current status in the update predicate.
- Added `spcrc_accept_critical_risk`, excluded from automatic administrator grants.
- Required a sanitized accountability note for every status transition; only its SHA-256 proof is included in the audit event.
- Made status-change audit events preserve native module and severity context.
- Restored capability-hook registration at runtime.
- Added a private Findings submenu with nonce and capability protected create/status actions.
- Captured the submenu hook suffix and loaded scoped admin assets only on that page.
- Added responsive table overflow rules.
- Expanded finding tests and added a standalone runtime capability-contract test.

## Boundaries

- The accountability note itself is not persisted in the public plugin database during this foundation cycle; only a one-way proof is logged. Detailed operational evidence remains in the private evidence system.
- Accepted-risk decisions require explicit capability delegation but do not yet implement dual approval.
- WordPress/MySQL runtime, Hostinger staging, responsive visual inspection and File 00/File 20 integration remain separate acceptance gates.
