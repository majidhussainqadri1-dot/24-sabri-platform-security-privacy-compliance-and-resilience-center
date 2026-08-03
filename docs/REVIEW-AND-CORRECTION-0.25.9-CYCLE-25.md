# Cycle 25 — Retention Ownership and Lease Review and Correction

**Review mode:** fresh destructive-job lease and deactivation race review  
**Scope:** retention lock acquisition, lease renewal, owner displacement, overflow deletion and unscheduling

## Defect F24-D059 — retention lease could be lost during destructive work

The 0.25.8 retention job acquired a bounded lock once and then performed age deletion, counting and overflow deletion without renewing or re-verifying ownership. If a slow query exceeded the lease, another worker could reclaim the lock and both workers could continue destructive work. Deactivation also deleted the option lock without proving ownership.

## Correction

- retention now uses exact-value `AtomicOptionLock` acquisition and release;
- ownership is renewed before the first delete, after age deletion and before overflow deletion;
- loss of ownership returns `retention_lock_lost` and stops subsequent destructive work;
- foreign/replacement locks cannot be refreshed or released;
- deactivation no longer deletes an option-backed lock owned by a possibly active request; expired cleanup remains atomic and uninstall owns final removal.

## Verification

`tests/cycle25-retention-ownership.php` provides ten assertions for renewal placement, explicit lock-loss handling, deactivation safety, owner refresh, displacement and foreign-release rejection. The full retention lifecycle test remains green.
