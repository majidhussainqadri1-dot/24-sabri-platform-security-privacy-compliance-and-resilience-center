# Migration — 0.25.1 to 0.25.2

1. Take and verify a staging backup before replacing the plugin package.
2. Install the 0.25.2 package over 0.25.1 on staging only.
3. On `plugins_loaded`, the guarded Upgrade Manager compares installed versions and runs `dbDelta()` only for File 24-owned tables.
4. Schema 0.25.2 extends the existing privacy-request table with bounded module-result evidence, dispatch-attempt count, optimistic lock version, next-retry time, last error code and completion time.
5. Existing security events, incidents, findings, risks, controls, privacy requests and module manifests are preserved.
6. Existing 0.25.1 privacy rows may have empty per-module evidence. They must not be automatically retried; reconcile or close them through an approved operational procedure.
7. Re-run System Checks; an unresolved upgrade error is a release blocker.
8. Confirm explicit role capabilities. Founder identity alone is not an operational security grant.
9. Verify the hourly privacy-recovery event is scheduled and is removed on deactivation.
10. Test privacy dispatch, pending completion callback, safe failed-module retry, stale dispatch detection and duplicate-side-effect prevention against real WordPress/MySQL staging.
11. Validate File 00, File 20, public browsing, REST, risk/control/incident forms and non-destructive repair.

No companion-module table, user record, exported personal data or native clinical record is migrated by File 24.
