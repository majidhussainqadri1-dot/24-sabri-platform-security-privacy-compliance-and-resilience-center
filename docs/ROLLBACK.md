# Rollback — Foundation 0.25.9

Rollback is code-first and evidence-preserving:

1. Put staging into the appropriate File 20 maintenance/read-only state when available.
2. Stop new privacy dispatch and inventory requests in `dispatching`, `pending`, `partial` or `recovery-required` state.
3. Freeze governance approvals, risk acceptance, security-state requests and control changes; preserve expiry and gap evidence.
4. Restore the prior reviewed File 24 package.
5. Do **not** drop File 24 tables or remove schema 0.25.5 columns automatically.
6. Preserve governance decisions, assurance rows, privacy evidence, audit gaps, risk/finding/incident/control rows and version truth.
7. Clear scheduled hooks only when the prior package does not own compatible callbacks.
8. Inspect all option-backed locks. Remove one only when the owner is proven absent/stale and the action is recorded; never delete an active foreign lock.
9. Do not retry privacy work merely because older code cannot interpret newer compensation or gap evidence.
10. Treat older-code inability to evaluate 0.25.9 evidence bindings as a reason to remain blocked, not as approval.
11. Reconcile audit gaps only after returning to 0.25.9 or a later compatible release through the authorized workflow.
12. Re-run prior-package checks and verify native modules still enforce their own authorization.
13. Use the previously tested full staging restore when code rollback does not restore integrity.
14. Record rollback, evidence preservation and later reconciliation in the private operational change/incident system.

Rollback acceptance requires login, anonymous public browsing, native permissions, database integrity, privacy reconciliation, governance-gap preservation, cron ownership and the Security Center fallback path to be tested.
