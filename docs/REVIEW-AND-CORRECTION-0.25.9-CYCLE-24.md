# Cycle 24 — Upgrade-Lock Stale-Takeover Review and Correction

**Review mode:** fresh migration-coordination and stale-lock adversarial review  
**Scope:** `UpgradeManager`, concurrent migrations, malformed lock state and owner-only release

## Defect F24-D058 — non-atomic stale upgrade-lock reclamation

The 0.25.8 upgrade lock used `get_option()`, `delete_option()` and `add_option()` as separate operations. During stale takeover, another worker could acquire the lock after deletion and then be affected by the first worker's subsequent operations. Release also depended on a separate read and delete.

## Correction

- `UpgradeManager` now uses `AtomicOptionLock`;
- stale takeover is an exact serialized-value compare-and-swap;
- release is an exact serialized-value compare-and-delete;
- active contention remains a transient `spcrc_upgrade_locked` condition and does not overwrite durable failure evidence;
- malformed or unverifiable lock state becomes the durable boot-blocking `spcrc_upgrade_lock_unavailable` error;
- failed owner release emits explicit operational evidence.

## Verification

`tests/cycle24-upgrade-lock-atomic.php` provides eleven assertions for contention, stale reclamation, ownership, foreign release rejection, exact release and malformed-lock preservation. The established upgrade suite was also updated to exercise the atomic option-table path.
