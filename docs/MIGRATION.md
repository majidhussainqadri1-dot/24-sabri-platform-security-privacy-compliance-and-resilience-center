# Migration — 0.25.8 to 0.25.9

1. Back up the staging database and plugin files through the approved provider workflow; retain only an opaque evidence reference in File 24.
2. Confirm no active upgrade, retention, audit-gap, security-state, governance-request or control-key lock exists. Never clear a live owner lock merely to force progress.
3. Install 0.25.9 over 0.25.8 on staging only.
4. Schema remains 0.25.5 because this corrective release changes coordination and compensation logic, not table shape.
5. Confirm activation/runtime verification, capabilities, `spcrc_retention_cleanup` and `spcrc_privacy_recovery_scan`.
6. Exercise active contention, expired-lock recovery, malformed-lock failure and owner-only release for each option-backed coordination path.
7. Exercise manifest zero-row heartbeat with identical and drifted canonical hashes.
8. Exercise privacy verification storage failure with successful and failed recovery-state compensation; unresolved gaps must block acceptance.
9. Exercise concurrent control upserts and audit-failure rollback on the same control key.
10. Verify uninstall on a disposable clone: ephemeral coordination locks are removed while durable evidence, schema/version truth and audit gaps remain preserved.
11. Re-run PHP 8.0/8.3 CI, source checksums, deterministic double build and ZIP integrity.
12. Validate live File 00/File 20 adapters, public browsing, REST minimization and external evidence providers.
13. Record staging acceptance, rollback evidence and Founder decision in the private operational system.

No companion-module table, exported personal data, native clinical record, raw vendor contract, secret, backup location or private evidence payload is migrated by File 24.
