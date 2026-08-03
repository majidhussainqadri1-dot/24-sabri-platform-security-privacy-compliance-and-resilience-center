# Cycle 28 — Control Upsert Concurrency Review and Correction

**Review mode:** fresh concurrency, audit-atomicity and rollback-integrity review  
**Scope:** `ControlRepository::upsert()`, control-key admission, audit evidence and compensation

## Defect F24-D062 — un-serialized control upserts

The Cycle 21 baseline performed a read, then update/insert, then audit, without a subject-scoped coordination lock. Two requests for the same `control_key` could both read the same pre-state and overwrite one another. More seriously, an audit-failure rollback from the older request could overwrite a newer successful update.

## Correction

- added a control-key-scoped `AtomicOptionLock`;
- refreshes owner-token lease before write, before audit and before compensation;
- distinguishes active contention from post-write ownership loss;
- records a bounded audit gap when ownership is lost after persistence;
- compare-binds update rollback to the exact `updated_at` written by the request;
- treats ambiguous zero-row updates as success only when the canonical row exactly matches the intended payload;
- emits explicit lock-release failure evidence without deleting another worker's lock.

## Verification

Dedicated Cycle 28 suite: **13 assertions** covering source contracts, active contention, expired-lock reclamation, owner-only release, post-write lock theft, audit-gap creation and exact rollback.

**Result:** corrected and regression-locked.
