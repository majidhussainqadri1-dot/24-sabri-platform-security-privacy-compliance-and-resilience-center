# Cycle 36 — Governance Audit-Gap Concurrency Review and Correction

**Review mode:** fresh audit-gap lost-update and fail-closed fallback review

## Defect F24-D070

The governance-specific audit-gap map used an unlocked read/modify/write sequence and ignored persistence failure. Concurrent decisions or reconciliation could overwrite unrelated gaps. More critically, if the specific gap could not be stored, a database-approved decision could appear usable despite missing audit evidence.

## Correction

- Governance gap mutation and reconciliation now use a dedicated atomic owner-token lock with lease renewal.
- Reconciliation re-reads the exact gap while holding the lock before auditing and clearing it.
- If the specific registry lock or write fails, a generic `governance-batch` fallback gap is stored through `AuditGapStore`.
- `hasAuditGap()` and `isApprovedFor()` recognize both specific and fallback evidence, so an unaudited decision remains unusable.
- Lock-release and total gap-record failure emit bounded diagnostic actions.

## Verification

`tests/cycle36-governance-audit-gap-concurrency.php` forces specific-lock contention during an approval audit failure and proves durable fallback evidence and exact decision-level fail-closed authorization.
