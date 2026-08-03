# Cycle 18 — Retention Concurrency Review and Correction

**Review mode:** fresh runtime-concurrency and evidence-retention audit
**Scope:** `RetentionManager`, retention scheduling, lock ownership, failure paths and regression tests

## Defect F24-D052 — non-atomic retention lock

The Cycle 17 implementation used `get_transient()` followed by `set_transient()`. That check-then-set sequence is not an atomic mutual-exclusion primitive: two cron workers can both observe no transient and both begin deleting security-event rows. This contradicted the plan's race-condition, bounded-query and fail-closed requirements.

## Correction

- replaced the normal WordPress path with atomic `add_option()` lock acquisition;
- stored a random owner token and bounded expiry;
- distinguished active contention from lock-storage failure;
- reclaimed expired locks;
- released the lock only when the stored token matches the current owner;
- retained a compatibility transient fallback only for non-WordPress test/edge environments;
- made deactivation/unscheduling remove both option and transient forms;
- expanded functional retention tests for contention, stale-lock takeover, lock-storage failure and owner cleanup;
- added `tests/cycle18-retention-concurrency.php`.

## Review result after correction

The original race is closed. Retention deletion cannot start through the normal WordPress path unless one worker atomically owns the canonical lock. All failure, hold and missing-table paths release only their own lock and remain auditable.
