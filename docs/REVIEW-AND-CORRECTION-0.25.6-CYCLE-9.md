# Review and Correction — 0.25.6 — Cycle 9

## Scope

Fresh comprehensive review followed by a separate adversarial review of File 24 foundation candidate 0.25.4 and the next assurance-registry milestone.

## Confirmed defects corrected

1. Malformed privacy evidence could create a canonical row before opaque-reference validation.
2. Activation and repair could claim success without a verified privacy-recovery schedule.
3. Module manifests used destructive replacement semantics and could rebind a key under concurrency.
4. Structured upgrade errors rendered as empty detail.
5. Compliance, vendor and backup assurance had no bounded first-class registry.
6. Successful plugin boot called nonexistent `registerHooks()` methods on Repair, RiskRepository, IncidentRepository and ControlRepository.
7. Same-version boot trusted version options without verifying required tables.
8. Failed activation could leave a partially created schedule.
9. Verified backup status did not require an opaque private evidence reference.
10. Backup evidence adapters could propagate unapproved upstream fields.
11. Final compliance/vendor determinations could be recorded without completed-review evidence.
12. Privacy native-proof adapters could be invoked before due-date and assignee validation.

## Corrective implementation

- Added pre-storage privacy evidence validation.
- Added schema `verify()` and same-version boot integrity checks.
- Added dual-schedule activation/upgrade/repair verification and activation cleanup.
- Replaced manifest `REPLACE` with guarded insert/update and identity collision detection.
- Added private Assurance Registry, capability, admin workflow, schema table and authorized status counts.
- Added evidence minimization, chronology checks, future-time checks and final-determination gates.
- Removed invalid success-path hook calls and added an actual successful-boot test.
- Added SPDX SBOM, license inventory, migration/rollback updates and deterministic packaging gates.

## Local verification

The reviewed local suite includes PHP syntax lint plus foundation, retention, upgrade, activation, boot-failure, successful boot, findings, capabilities, privacy orchestration, privacy policy, privacy verification, privacy recovery, admin assets and Cycle 9 adversarial contracts.

Automated success remains distinct from staging acceptance and production readiness.

## Remaining external acceptance gates

- real WordPress fresh activation and same-version damaged-schema test;
- MySQL/MariaDB migration and rollback;
- File 00 and File 20 staging integrations;
- real backup/restore drill and external logging adapter;
- qualified legal/compliance applicability review;
- accessibility, responsive and browser acceptance;
- independent abuse-case and penetration testing;
- Founder approval before merge/live deployment.
