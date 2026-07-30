# Migration — 0.25.0 to 0.25.1

1. Take and verify a staging backup before activation.
2. Install the 0.25.1 package over 0.25.0 on staging.
3. On `plugins_loaded`, the guarded Upgrade Manager compares the installed schema and runs `dbDelta()` only for File 24-owned tables.
4. Schema 0.25.1 adds the risk and control tables and verifies every required table before recording success.
5. Existing event, incident, finding, privacy and manifest records are preserved.
6. Re-run System Checks; an unresolved upgrade error is a release blocker.
7. Confirm explicit role capabilities. Founder identity alone is not an operational security grant.
8. Validate File 00, File 20, public browsing, REST, risk/control/incident forms and non-destructive repair.

No companion-module table or user record is migrated by File 24.
