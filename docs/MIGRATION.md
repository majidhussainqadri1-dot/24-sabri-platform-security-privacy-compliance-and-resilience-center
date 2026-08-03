# Migration — 0.25.7 to 0.25.8

1. Back up the staging database and plugin files through the approved provider workflow; retain an opaque evidence reference outside this repository.
2. Confirm no active File 24 upgrade, retention, security-state or audit-gap mutation lock exists. Do not manually clear a live owner lock.
3. Install 0.25.8 over 0.25.7 on staging only.
4. File 24 retains schema version 0.25.5 because no table shape changes in this corrective release.
5. Upgrade verification now inspects every required column in all nine owned tables. Any missing column blocks normal File 24 runtime before version success is recorded.
6. Confirm `spcrc_retention_cleanup`, `spcrc_privacy_recovery_scan`, capabilities and version-state integrity.
7. Exercise concurrent retention and audit-gap paths; active contention must fail closed and expired locks must recover without losing evidence.
8. Exercise privacy retries with never-started, explicitly `retry-safe-`, uncertain and completed native-module outcomes. Only the first two categories may replay.
9. Verify uninstall behavior on a disposable staging clone: capabilities and ephemeral locks are removed while events, risks, findings, incidents, controls, privacy requests, manifests, governance, assurance rows, audit gaps and schema/version evidence remain preserved.
10. Re-run the full PHP 8.0/8.3 CI suite, deterministic double build, ZIP integrity and checksum validation.
11. Validate real File 00 step-up, File 20 advisory-state integration, public browsing, REST minimization and external evidence adapters.
12. Record staging acceptance, rollback evidence and Founder decision in the private operational system.

No companion-module table, exported personal data, native clinical record, raw vendor contract, secret, backup location or private evidence payload is migrated by File 24.
