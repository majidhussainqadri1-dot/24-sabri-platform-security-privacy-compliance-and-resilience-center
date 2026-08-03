# Cycle 20 — Audit-Gap Concurrency Review and Correction

**Review mode:** fresh evidence-integrity, lost-update and reconciliation-race audit
**Scope:** bounded audit-gap creation, reconciliation, stale locks, owner release and operational observability

## Defect F24-D054 — lost audit gaps under concurrent mutation

`AuditGapStore::record()` and `AuditGapStore::reconcile()` both used an unguarded read-modify-write sequence on WordPress options. Two simultaneous failures could read the same old array and each write a different successor, losing one release-blocking gap. A reconciliation could likewise remove one gap while overwriting another gap recorded during the same interval.

The defect endangered precisely the evidence that should remain visible when canonical audit storage fails, and therefore contradicted fail-closed, race-condition and audit-integrity requirements.

## Correction

- introduced one canonical atomic `add_option()` mutation lock for all audit-gap writes;
- stored an owner token and bounded expiry;
- reclaimed expired orphan locks while rejecting active contention;
- wrapped both record and reconcile read-modify-write sequences in lock ownership;
- used `finally` blocks so every return path releases only its own lock;
- preserved existing gaps when contention occurs;
- emitted an operational action when record creation cannot obtain the lock;
- returned a typed reconciliation error rather than mutating uncertain state;
- added `tests/cycle20-audit-gap-concurrency.php` with functional contention, stale-lock, preservation, reconciliation and ownership assertions.

## Review result after correction

Audit-gap mutations are now serialized through an atomic, expiring and owner-bound lock. A concurrent request can no longer silently replace another release blocker. Active contention fails closed, stale locks recover, and reconciliation removes only the selected gap while preserving all others.
