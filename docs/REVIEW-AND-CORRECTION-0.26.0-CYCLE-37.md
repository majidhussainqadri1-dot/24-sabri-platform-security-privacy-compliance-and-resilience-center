# File 24 — Review and Correction Cycle 37

**Defect:** F24-D071 — Governance approval expiry TOCTOU.

A pending decision was checked for expiry before the database update, but expiry was not part of the atomic write predicate. A request could cross its deadline between the read and update and still be approved.

## Correction

The approval update now requires `expires_at > now` in the same SQL predicate as UUID, pending status and lock version. A zero-row result is re-read; an expired request is marked expired and returns a dedicated fail-closed error. No approval audit event is emitted.

## Verification

`tests/cycle37-governance-expiry-atomic.php` simulates expiry immediately before the atomic update and proves that approval is denied, no approver is bound and normal non-expired approval still succeeds.
