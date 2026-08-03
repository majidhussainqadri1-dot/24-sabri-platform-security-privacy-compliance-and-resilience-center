# Sabri Platform Security, Privacy, Compliance and Resilience Center

File 24 is the central security-governance and assurance plane for the Sabri Social Homeopathy Platform. Native modules retain authentication, authorization and canonical data ownership.

## Foundation scope — eight-round corrective candidate 0.25.9

This reviewed Foundation establishes:

- a versioned module-security manifest registry with persisted identity binding, guarded writes and zero-row concurrency verification;
- a private role-aware Security Center with separately gated governance request, approval and reconciliation surfaces;
- bounded security-event and audit-gap storage with recursive redaction and external-event hooks;
- audit-atomic risk, incident, finding and control workflows with governed, expiring risk acceptance;
- exact-value atomic option locks with owner tokens, bounded leases, stale reclamation and owner-only release;
- a bounded Assurance Registry for compliance applicability, vendor review and backup/restore evidence metadata;
- verified, replay-resistant privacy orchestration with storage-bound retry safety and compensation-failure evidence;
- fail-closed activation/runtime boot, nine-table schema verification, upgrade locking and downgrade prevention;
- non-destructive repair that verifies schema, capabilities, schedules and version state;
- File 00 and File 20 adapters without duplicating their authority;
- sanitized private status and public Trust Center REST payloads;
- reproducible packaging, source checksums, SPDX SBOM, license inventory and PHP 8.0/8.3 CI gates.

File 24 does **not** replace File 00 identity, native-module authorization, File 20 shell enforcement, hosting security, a WAF, a SIEM, legal counsel, a backup engine, immutable off-site evidence or independent penetration testing.

## Assurance boundary

The Assurance Registry stores bounded status metadata and opaque references only. It must never contain raw contracts, credentials, secrets, backup locations, identity documents, forensic payloads, patient records or private incident playbooks.

A compliance entry records applicability status; it is not an automatic legal-compliance claim. Backup status may be `verified` only when successful-backup evidence, a later restore-test timestamp and an opaque private evidence reference are present.

## Repository safety

This public repository contains sanitized source and documentation only. Live vulnerabilities, detailed risk registers, forensic evidence, vendor contracts, backup locations, keys, secrets and incident playbooks belong in approved private operational systems.

## Development status

Audit or compensation failures create bounded, independently keyed release blockers rather than being overwritten or silently treated as success. Generic operational gaps can be reconciled only through a private capability-, nonce-, File 00 step-up-, evidence- and audit-gated workflow.

The 0.25.9 implementation is a reviewed Foundation candidate and is not production-ready. Automated checks do not replace real WordPress/MySQL activation, migration and rollback, Hostinger staging, live File 00/File 20 integration, accessibility/browser acceptance, restore drills, provider validation, abuse testing, legal review or independent penetration testing.

## Build and QA

```bash
php tests/run.php
php tests/retention.php
php tests/upgrade.php
php tests/activation-cycle9.php
php tests/boot-failure.php
php tests/findings.php
php tests/runtime.php
php tests/privacy.php
php tests/privacy-policy.php
php tests/privacy-verification.php
php tests/privacy-recovery.php
php tests/admin-assets.php
php tests/cycle9.php
php tests/plugin-boot-cycle9.php
php tests/governance.php
php tests/cycle12-adversarial.php
php tests/cycle13-exhaustive.php
php tests/cycle14-extraordinary.php
php tests/cycle15-illuminative.php
php tests/cycle16-closure.php
php tests/cycle17-illuminative.php
php tests/cycle18-retention-concurrency.php
php tests/cycle19-privacy-retry-safety.php
php tests/cycle20-audit-gap-concurrency.php
php tests/cycle21-schema-release-closure.php
php tests/cycle22-manifest-heartbeat-race.php
php tests/cycle23-governance-request-lock.php
php tests/cycle24-upgrade-lock-atomic.php
php tests/cycle25-retention-ownership.php
php tests/cycle26-audit-gap-lock-lease.php
php tests/cycle27-security-state-atomic.php
php tests/cycle28-control-upsert-lock.php
php tests/cycle29-privacy-verification-compensation.php
php tests/cycle29-eight-round-release-closure.php
./tools/build-release.sh
```

The installable package and SHA-256 receipt are created under `build/`.
