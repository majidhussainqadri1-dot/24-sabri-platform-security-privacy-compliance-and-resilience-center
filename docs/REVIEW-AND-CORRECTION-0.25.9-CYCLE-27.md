# Cycle 27 — Security-State Atomicity and Audit-Gap Review and Correction

**Review mode:** fresh enforcement-request concurrency and evidence-integrity review  
**Scope:** security-state option mutations, stale locks, audit rollback, consumer visibility and gap bounding

## Defect F24-D061 — state-lock takeover and custom audit-gap storage were unsafe

Security-state mutations used separate read/delete/add lock operations. The registry also maintained its own unbounded, unlocked audit-gap option. A state request whose audit rollback failed could remain visible to File 20 consumers despite missing required audit evidence.

## Correction

- state mutations now use exact-value atomic option locking and owner-only release;
- write and rollback paths renew ownership before durable option changes;
- active, malformed or lost lock ownership fails closed;
- state audit failures now use the central `AuditGapStore`, inheriting serialized writes and the 100-record bound;
- requests with unresolved request-specific audit gaps are excluded from consumer-visible state output;
- ordinary resolution refuses a request carrying unresolved audit evidence;
- state-gap write failure and lock-release failure are observable.

## Verification

`tests/cycle27-security-state-atomic.php` provides thirteen assertions covering contention, stale reclamation, exact release, centralized gap storage, enforcement visibility blocking, resolution blocking, bounded growth and source contracts. The prior Cycle 15 adversarial tests remain applicable.
