# Cycle 33 — Audit-Gap Capacity Review and Correction

**Review mode:** fresh bounded-registry overflow and release-blocker preservation review

## Defect F24-D067

When the audit-gap registry exceeded 100 entries, it silently sliced off the oldest unresolved gaps. A sustained failure burst could therefore erase a critical release blocker without reconciliation or durable audit evidence.

## Correction

A full registry now fails closed: the new gap is rejected, a bounded capacity action is emitted, and all existing unresolved gaps remain intact. No unresolved gap is evicted merely to admit another.

## Verification

`tests/cycle33-audit-gap-capacity.php` fills the registry to its bound and proves overflow rejection, count preservation, byte-equivalent state preservation, and survival of both oldest and newest existing gaps.
