# Cycle 23 — Governance Duplicate-Request Concurrency Review and Correction

**Review mode:** fresh race-condition and separation-of-duty admission review  
**Scope:** governance request deduplication, stale-lock takeover, owner-only release and malformed-lock behavior

## Defect F24-D057 — check-then-insert governance duplication race

The 0.25.8 request path queried for a pending decision and then inserted a new row without a serialized subject-level admission lock. Two concurrent requests for the same decision type and subject could both observe no duplicate and create parallel pending approvals.

## Correction

- introduced `AtomicOptionLock`, using exact serialized-value compare-and-swap/delete against the WordPress options table;
- added a subject-scoped lock derived from decision type and subject key;
- kept duplicate lookup, insert, audit and rollback within the owner-token lock;
- active contention, malformed lock state and failed stale takeover now fail closed;
- release is conditional on the exact owner token.

## Verification

`tests/cycle23-governance-request-lock.php` provides ten assertions covering active contention, foreign-lock preservation, atomic stale reclamation, exact release, duplicate rejection and malformed-lock fail-closed behavior.
