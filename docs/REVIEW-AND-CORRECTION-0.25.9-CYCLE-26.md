# Cycle 26 — Audit-Gap Lock and Lease Review and Correction

**Review mode:** fresh evidence-registry concurrency and lock-expiry review  
**Scope:** audit-gap record/reconcile mutations, stale takeover, lease renewal and owner-only release

## Defect F24-D060 — audit-gap stale takeover and mid-operation expiry were not atomic

The 0.25.8 audit-gap registry reclaimed stale locks through separate read/delete/add operations. Reconciliation could also spend time writing authorization audit evidence and then mutate the option after its 30-second lease had expired.

## Correction

- audit-gap locking now uses exact serialized-value compare-and-swap/delete;
- active and malformed lock states fail closed and preserve evidence;
- both record and reconcile paths renew ownership immediately before committing option changes;
- record-side ownership loss emits `spcrc/audit_gap_lock_lost` and does not write;
- reconciliation returns `spcrc_audit_gap_lock_lost` when authorization evidence succeeds but mutation ownership is no longer valid;
- release is exact-owner-only and release failure is observable.

## Verification

`tests/cycle26-audit-gap-lock-lease.php` provides thirteen assertions for source contracts, active contention, evidence preservation, atomic stale reclamation, exact release and malformed-lock behavior. The Cycle 20 concurrency suite remains green with stronger assertions.
