# Rollback — Foundation 0.25.6

Rollback is code-first and evidence-preserving:

1. Put staging into the appropriate File 20 maintenance/read-only state when available.
2. Stop new privacy dispatch and record requests in `dispatching`, `pending`, `partial` or `recovery-required` state.
3. Export a sanitized list of Assurance Registry keys/statuses only; do not export private evidence through this repository.
4. Restore the prior reviewed File 24 package.
5. Do **not** drop File 24 tables automatically. The assurance table and privacy evidence columns remain preserved.
6. Clear `spcrc_privacy_recovery_scan` and the File 24 retention schedule only when the prior package does not own compatible callbacks.
7. Do not retry privacy work merely because older code cannot interpret newer evidence.
8. Re-run the prior package checks and confirm native modules still enforce their own authorization.
9. If runtime integrity is not restored, use the previously tested full staging backup/restore procedure.
10. Record rollback and reconciliation in the private operational change/incident system.

Rollback acceptance requires login, anonymous public browsing, native permissions, database integrity, pending privacy reconciliation, cron ownership and the Security Center fallback path to be tested.
