# File 24 Foundation — Review and Corrections

Date: 2026-07-30
Reviewed head: `b48f7d13228de7ac0596a45c0fc2b436e77769d0`
Corrective target: `0.25.1`

## Corrected release blockers

1. **Overbroad Founder privilege bypass** — removed blanket `map_meta_cap` elevation. Explicit role/capability assignment is now required.
2. **Security-state requests were request-memory only** — added bounded database persistence, expiry, resolution and audit evidence.
3. **Privacy dispatch treated absent handlers as accepted** — null handlers now fail explicitly; empty module lists fail; metadata status is persisted.
4. **Action-only privacy dispatch could not return results** — added result-bearing `spcrc/privacy_dispatch` filter and completion action.
5. **Audit writes could silently fail** — persistence failures now return `WP_Error` and emit a failure hook.
6. **Audit storage was not actually bounded** — added depth/item/byte limits, daily retention scheduling and batch pruning.
7. **Audit redaction was key-only** — expanded sensitive-key redaction and Bearer/private-key value redaction.
8. **Public Trust payload could be extended with arbitrary fields** — added a final server-side allowlist and canonical limitations.
9. **Upgrade path lacked locking, downgrade protection and capability repair** — added all three and schema verification.
10. **Uninstall left stale privileges and jobs** — capabilities and scheduled jobs are now removed while evidence tables remain preserved.
11. **Module key collision could silently overwrite posture** — conflicting duplicate manifests are rejected.
12. **System checks produced false assurance** — companion-module, schema, retention and structured backup evidence checks were added; availability is labeled as reported, not independently proven.
13. **Private REST status lacked explicit cache/index controls** — added `private, no-store` and noindex headers.
14. **CI did not test the minimum PHP version or functional contracts** — added PHP 8.0/8.3 matrix, regression contracts, checksum verification and ZIP smoke test.
15. **Public availability evidence could still be elevated by a later filter** — canonical program status and verified booleans are now immutable after evidence verification; stale evidence is rejected.
16. **Privacy request payloads could fan arbitrary data out to every module** — module handlers now receive a bounded metadata allowlist only.
17. **Privacy dispatch was not idempotent** — completed or active request UUIDs are no longer silently reprocessed; privileged retries are explicit.
18. **Persisted module identities could be hijacked on a later request** — owner/name changes now require an explicit authorization filter, and arbitrary manifest fields are discarded.
19. **Unbounded identifiers could exceed database columns** — event types and module keys are truncated to schema limits before persistence.
20. **Duplicate security-state requests could flood the registry** — identical open module/state requests are suppressed.
21. **Retention failures were reported as successful completion** — database failures now produce partial/high-risk evidence and a dedicated failure hook.
22. **Backup, restore, external-log and Trust evidence could remain stale indefinitely** — bounded freshness checks were added.
23. **Upgrade downgrade handling could leave incompatible runtime active** — incompatible schema now pauses File 24 runtime and displays a recovery notice.
24. **Schema verification checked tables only** — required columns are now verified before activation or upgrade succeeds.

## Remaining external gates

- real WordPress fresh activation and upgrade testing;
- File 00 and File 20 end-to-end adapters;
- Hostinger staging runtime and database acceptance;
- backup/restore drill evidence;
- external logging delivery test;
- accessibility and browser acceptance;
- independent penetration testing;
- Founder acceptance and merge authorization.
