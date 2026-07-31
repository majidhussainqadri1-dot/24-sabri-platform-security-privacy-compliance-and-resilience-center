# Migration — 0.25.4 to 0.25.6

1. Take and verify a staging backup before replacing the package.
2. Install 0.25.6 over 0.25.4 on staging only.
3. The guarded Upgrade Manager verifies all File 24 tables and creates `wp_spcrc_assurance_records` through `dbDelta()`.
4. Schema version advances from 0.25.3 to 0.25.4; plugin version advances to 0.25.6 only after schema, capabilities, retention schedule, privacy-recovery schedule and version-state verification succeed.
5. Existing events, incidents, findings, risks, controls, privacy requests and manifests remain preserved.
6. Existing manifests are read with their stored JSON identity. A key/name/owner collision blocks registration rather than overwriting the record.
7. Existing privacy rows are not automatically replayed. Legacy rows without verified evidence require reconciliation.
8. The new Assurance Registry begins empty. Do not import raw contracts, secrets, backup locations or personal data. Enter only bounded metadata and opaque references.
9. A backup may be marked `verified` only after a successful backup and later restore test are privately evidenced.
10. Re-run all System Checks and verify the two required cron schedules.
11. Test fresh activation, same-version missing-table detection, upgrade, repair, deactivation and rollback on real WordPress/MySQL staging.
12. Validate File 00, File 20, public browsing, privacy dispatch/callback/retry, assurance permissions and REST minimization.

No companion-module table, exported personal data, native clinical record, raw vendor contract or backup payload is migrated by File 24.
