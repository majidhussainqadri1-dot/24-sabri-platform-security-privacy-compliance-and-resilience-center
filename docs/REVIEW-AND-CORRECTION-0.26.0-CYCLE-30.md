# Cycle 30 — Expired Lock Lease Review and Correction

**Review mode:** fresh lease-expiry and split-brain concurrency review

## Defect F24-D064

`AtomicOptionLock::refresh()` verified the token but did not verify that the lease was still live. A delayed worker could therefore renew an already expired lease. Another worker may already have observed that lease as stale and begun takeover, creating an avoidable split-brain race.

## Correction

Refresh now fails closed when `expires_at <= time()`. Only the current owner of a still-live lease may renew it. The rejected refresh leaves the stored lock unchanged.

## Verification

`tests/cycle30-expired-lock-refresh.php` proves expired-owner rejection, non-mutation, active renewal, owner preservation, expiry extension and foreign-owner rejection.
