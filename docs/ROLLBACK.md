# Rollback — Foundation 0.25.2

Rollback is code-first and evidence-preserving:

1. Put the staging site into the appropriate File 20 maintenance/read-only state when available.
2. Stop new privacy-request dispatch and record any request currently in `dispatching`, `pending`, `partial` or `recovery-required` state.
3. Restore the prior reviewed File 24 plugin package.
4. Do **not** drop File 24 tables automatically. The 0.25.2 privacy columns and evidence remain preserved for later controlled migration or reinstallation.
5. Do not retry a privacy operation merely because the older code cannot interpret per-module evidence. Native completion or reconciliation must determine whether a side effect already occurred.
6. Re-run the prior version's checks and verify native modules still enforce their own authorization.
7. Confirm the 0.25.2 privacy-recovery cron is absent after rollback or explicitly clear `spcrc_privacy_recovery_scan`.
8. If runtime integrity is not restored, use the previously tested full staging backup/restore procedure.
9. Record the rollback as an incident/change event outside the public repository.

A rollback is not accepted until login, public browsing, native permissions, database integrity, pending privacy-operation reconciliation and the Security Center fallback path are tested.
