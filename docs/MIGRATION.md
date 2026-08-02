# Migration — 0.25.6 to 0.25.7

1. Take and independently verify a staging backup before replacing the package.
2. Install 0.25.7 over 0.25.6 on staging only.
3. The Upgrade Manager acquires the atomic `spcrc_upgrade_lock`. Lock contention fails closed; an expired lock may be replaced only by the bounded stale-lock path. The lock is released in `finally`.
4. The manager rejects unsafe downgrade when stored plugin/schema versions exceed the package being run.
5. Idempotent `dbDelta()` creates `wp_spcrc_governance_decisions` and adds governance-binding/expiry fields to risks/findings plus incident evidence fields.
6. Schema advances from 0.25.4 to 0.25.5. Plugin version advances to 0.25.7 only after all nine tables, governed columns, capabilities, retention schedule, privacy-recovery schedule and version-state verification succeed.
7. Existing events, incidents, findings, risks, controls, privacy requests, manifests and assurance records remain preserved.
8. Existing module manifests are enriched on their next native registration; no module key/name/owner may be rebound.
9. Existing accepted-risk records are not retroactively treated as governance-approved. Re-open and re-assess them before relying on acceptance.
10. Governance decisions contain only bounded metadata, hashes and opaque evidence references. Raw evidence, credentials, legal advice and operational playbooks remain outside the public control plane.
11. Explicitly delegate `spcrc_request_governance_decision`, `spcrc_approve_governance_decision` and `spcrc_accept_critical_risk` according to separation of duties. Approval and critical-risk acceptance are not auto-granted.
12. Verify the File 00 step-up contract; absent, stale or purpose-mismatched assurance must fail closed.
13. Inspect `spcrc_governance_audit_gap` for independently keyed gaps. Do not delete it manually; use the authorized, step-up-protected reconciliation workflow after audit storage is healthy.
14. Verify File 20 advisory request and resolution authorization bridges, duplicate suppression, 24-hour expiry and native enforcement ownership.
15. Re-run System Checks, the full PHP 8.0/8.3 CI suite, fresh activation, upgrade, repair, deactivation and rollback on real WordPress/MySQL staging.
16. Validate File 00, File 20, public browsing, privacy dispatch, governance approval, accepted-risk binding, assurance permissions, REST minimization and cron ownership.

No companion-module table, exported personal data, native clinical record, raw vendor contract, secret, backup location or private evidence payload is migrated by File 24.
