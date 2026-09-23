# Files 00–26 Integration Matrix — Corrective Addendum

## Permanent numbering

The matrix now contains contiguous definitions for every permanent numbered file from **00 through 26**. Completion requires exactly 27 entries and exact keys `0..26`; merely having Files 00 and 25 no longer produces a false positive.

## Corrected ownership records

### File 13 — historical compatibility only

File 13 does not own the active welcome experience. Its allowed role is migration/compatibility detection, with legacy activation gated.

### File 20 — Unified Application Shell

File 20 owns platform-wide welcome invocation and frequency. The first eligible visit may show the intro once; dismissal suppresses it for at least thirty days; storage failure must never block the site.

### File 25 — Public UI and Visual Experience

File 25 owns welcome presentation, green-accent visual treatment, RTL, responsive behavior, focus management, reduced motion and accessibility.

### File 26 — Search, Discovery, Recommendations, Knowledge Graph and Classification

File 26 is the canonical owner of federated search, derivative indexes, query understanding, ranking, recommendations, taxonomy/classification and owner-sourced knowledge-graph projections. File 24 assures:

- no private/pending/deleted/suspended leakage;
- deletion and stale-index reconciliation;
- recommendation consent and controls;
- doctor-ranking fairness and no donation/payment/favoritism advantage;
- versioned, auditable and rollbackable policy experiments.

File 26 is high-risk. Missing or incompatible contract evidence gates ranking/recommendation experiments and privileged discovery writes.

## Conditional modules

CF-01 through CF-04 remain conditional planning identifiers, not permanent numbered files. File 24 may record assurance contracts for them without claiming activation or transferring native ownership.


## Machine-readable fail-safe contract

Every permanent matrix row now exposes `contract_version`, `failure_mode`, `degraded_behavior`, `user_message`, `alert_owner`, `recovery_owner` and `exit_criteria`. `PlatformIntegrationMatrix::complete()` verifies these fields in addition to exact 00–26 numbering.

## Conditional cross-plan assurance

Traffic Analytics, Disease Intelligence and CF-04 Central Media are encoded separately in `ConditionalIntegrationCatalog`. They do not become numbered files and cannot be activated merely by repository presence.
