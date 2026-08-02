# Sabri Platform Security, Privacy, Compliance and Resilience Center

File 24 is the central security-governance and assurance plane for the Sabri Social Homeopathy Platform. Native modules retain their own authentication, authorization and canonical data ownership.

## Foundation scope — corrective candidate 0.25.7

This reviewed foundation establishes:

- a versioned module-security manifest registry with persisted identity binding, guarded updates and concurrency detection;
- a private role-aware Security Center dashboard with separately gated governance request, approval and reconciliation surfaces;
- bounded security-event storage with recursive redaction and external-event hooks;
- audit-atomic risk, incident, control and security-finding workflows with governed, expiring risk acceptance;
- a bounded Assurance Registry for compliance applicability, vendor review and backup/restore evidence metadata;
- verified, replay-resistant privacy orchestration that rejects malformed verification evidence before canonical request storage;
- bounded retry and stale-dispatch recovery without automatic replay of uncertain native side effects;
- fail-closed activation/runtime boot, deep table-and-column verification, migration locking and unsafe-downgrade prevention;
- non-destructive repair that verifies schema, capabilities, schedules and version state;
- File 00 and File 20 adapters without duplicating their authority;
- sanitized private status and public Trust Center REST payloads;
- audit-gap-aware System Checks, reproducible packaging, checksums, SPDX SBOM, license inventory and PHP 8.0/8.3 CI gates.

File 24 does **not** replace File 00 identity, native-module authorization, File 20 shell enforcement, hosting security, a WAF, a SIEM, legal counsel, a backup engine, immutable off-site evidence or independent penetration testing.

## Assurance boundary

The Assurance Registry stores only bounded status metadata and opaque references. It must never contain raw contracts, credentials, secrets, backup locations, identity documents, forensic payloads, patient records or private incident playbooks.

A compliance entry records applicability status; it is not an automatic claim of legal compliance. A backup may be marked `verified` only when a successful-backup timestamp, a later restore-test timestamp and an opaque private evidence reference are present.

## Repository safety

This public repository contains sanitized source and documentation only. Live vulnerabilities, detailed risk registers, forensic evidence, vendor contracts, backup locations, keys, secrets and incident playbooks belong in approved private operational systems.

## Development status

Audit failures in canonical, privacy, retention, recovery and repair paths create bounded, independently keyed release blockers rather than being overwritten or silently treated as success. Generic operational gaps can be reconciled only through a private capability-, nonce-, File 00 step-up-, evidence- and audit-gated workflow.

The 0.25.7 implementation is a reviewed Foundation candidate with declared PHP 8.0 compatibility and is not production-ready. Automated checks do not replace real WordPress activation, MySQL/MariaDB migration and rollback, Hostinger staging, File 00/File 20 integration, accessibility review, restore drills, abuse testing or independent security acceptance.

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
./tools/build-release.sh
```

The installable package and SHA-256 receipt are created under `build/`.
