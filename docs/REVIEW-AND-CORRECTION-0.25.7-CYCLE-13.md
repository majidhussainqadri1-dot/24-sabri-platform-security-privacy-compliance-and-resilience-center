# Review and Correction — 0.25.7 — Cycle 13

## Review method

A fresh source review was performed after Cycle 12 rather than relying on its green tests. The review targeted production-only paths, state concurrency, audit failure, uninstall hygiene, schema columns, upgrade/downgrade behavior and reconciliation of failed governance evidence.

## Defects found and corrected

1. `Schema::verify()` referenced a table map that was not initialized on the real-column inspection path. The verifier now initializes the canonical table map and the test database exercises governed columns.
2. Security-state requests accepted sensitive reasons, excessive explicit expiry, duplicate open requests and permissive programmatic calls. Requests now require a human capability or explicit authorization contract, reject sensitive reasons, cap lifetime at 24 hours, suppress duplicates and use a bounded mutation lock.
3. Security-state request/resolution persistence could survive an audit insert failure. Both paths now roll back; an explicit audit-gap marker is recorded only if rollback itself fails.
4. Uninstall capability cleanup omitted newer findings, assurance and governance capabilities. The complete capability inventory is now removed while evidence tables remain preserved.
5. Governance audit-gap state supported only one failed decision and could overwrite earlier gaps. It now stores independently keyed gaps, supports the old option shape and provides capability-, separation- and step-up-protected reconciliation.
6. Upgrade execution lacked an atomic migration lock and explicit downgrade prevention. Both were added, with stale-lock recovery and guaranteed lock release.
7. System Check verified tables but not governed columns. It now consumes the same deep schema verifier used by activation and upgrade.
8. Incident and control repositories were instantiated with an audit logger but did not own audit-integrity behavior. They now create canonical audit events and roll back their database mutation when the event cannot be stored.
9. Risk and finding creation/status changes could remain stored without their required audit event. Creation and high-risk transitions now roll back; bulk expiry reopening records an explicit audit-gap marker if audit storage is unavailable.
10. Finding accountability notes and central risk/finding/control/incident titles now reject detected sensitive material.
11. The private dashboard duplicated repository success audits. Duplicate success events were removed; repositories remain the canonical mutation-audit owners.
12. Governance navigation assumed an approver was also a requester. View, request and approval surfaces are now independently capability-gated.

## Automated evidence

`tests/cycle13-exhaustive.php` contains 50 assertions covering real-column schema failure, security-state authorization/expiry/locking/rollback, multi-gap governance reconciliation, audit-atomic canonical records, risk/finding transition rollback, uninstall capability hygiene and source contracts.

## Truth boundary

Cycle 13 closes the defects known from this review. It does not convert repository evidence into Hostinger staging, external-provider, legal, penetration-test, restore-drill, production or operational evidence.
