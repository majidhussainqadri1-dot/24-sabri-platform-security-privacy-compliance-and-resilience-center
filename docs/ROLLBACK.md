# Rollback — Foundation 0.25.1

Rollback is code-first and evidence-preserving:

1. Put the staging site into the appropriate File 20 maintenance/read-only state when available.
2. Restore the prior File 24 plugin package.
3. Do **not** drop File 24 tables automatically; 0.25.1 risk/control records remain preserved for a later controlled migration.
4. Re-run the prior version's checks and verify native modules still enforce their own authorization.
5. If runtime integrity is not restored, use the previously tested full staging backup/restore procedure.
6. Record the rollback as an incident/change event outside the public repository.

A rollback is not accepted until login, public browsing, native permissions, database integrity and the Security Center fallback path are tested.
