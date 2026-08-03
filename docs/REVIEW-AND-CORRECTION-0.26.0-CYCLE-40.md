# File 24 — Review and Correction Cycle 40

**Defect:** F24-D074 — Assurance create rollback treated a zero-row delete as success and used an unlocked bespoke gap registry.

A failed audit followed by a zero-row delete could be reported as successfully rolled back even though the assurance row remained. The fallback gap mutation also bypassed the central serialized audit-gap store.

## Correction

Creation rollback now succeeds only when exactly one row is deleted. Any rollback failure is registered through `AuditGapStore`, and `spcrc_assurance_audit_gap` is now a centrally managed reconciliation category.

## Verification

`tests/cycle40-assurance-audit-rollback.php` forces an audit failure and zero-row delete, then proves the remaining row is accompanied by a durable, centrally managed assurance gap.
