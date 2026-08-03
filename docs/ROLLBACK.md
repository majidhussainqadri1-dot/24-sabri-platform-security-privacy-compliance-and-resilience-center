# Rollback — Foundation 0.25.8

Rollback is code-first and evidence-preserving:

1. Put staging into the appropriate File 20 maintenance/read-only state when available.
2. Stop new privacy dispatch and record requests in `dispatching`, `pending`, `partial` or `recovery-required` state.
3. Freeze new governance requests, approvals, risk acceptance and security-state requests; preserve their current records and expiry evidence.
4. Export only a sanitized list of Assurance Registry keys/statuses and governance decision IDs/statuses. Do not export private evidence through this repository.
5. Restore the prior reviewed File 24 package.
6. Do **not** drop File 24 tables or remove 0.25.5 governed columns automatically. Governance decisions, audit-gap markers, assurance rows and privacy evidence remain preserved for forward recovery.
7. Clear `spcrc_privacy_recovery_scan` and the File 24 retention schedule only when the prior package does not own compatible callbacks.
8. Inspect `spcrc_upgrade_lock`, `spcrc_retention_lock`, `spcrc_security_state_lock` and `spcrc_audit_gap_store_lock`. Remove an option only when its owner is proven absent/stale and the action is recorded; never clear an active lock to force progress.
9. Do not retry privacy work merely because older code cannot interpret newer evidence.
10. Do not treat an older package's inability to evaluate 0.25.8 governance and evidence-integrity binding as approval. Re-open accepted risks/findings or keep them blocked until the current governed package is restored.
11. Preserve every independently keyed governance/audit gap. Reconcile only through the current authorized workflow after returning to 0.25.8 or a later compatible release.
12. Re-run prior-package checks and confirm native modules still enforce their own authorization.
13. If runtime integrity is not restored, use the previously tested full staging backup/restore procedure.
14. Record rollback, evidence preservation and later reconciliation in the private operational change/incident system.

Rollback acceptance requires login, anonymous public browsing, native permissions, database integrity, pending privacy reconciliation, governance-gap preservation, cron ownership and the Security Center fallback path to be tested.
