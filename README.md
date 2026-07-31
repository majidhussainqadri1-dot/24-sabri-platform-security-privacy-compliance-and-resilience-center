# Sabri Platform Security, Privacy, Compliance and Resilience Center

File 24 is the central security-governance and assurance layer for the Sabri Social Homeopathy Platform.

## Foundation scope (0.25.1)

This corrective foundation establishes:

- a versioned, bounded module-security manifest registry;
- a private role-aware Security Center dashboard;
- bounded security-event storage with recursive redaction and external-event hooks;
- operational security-finding intake and controlled status lifecycle contracts;
- a private findings workflow with concurrency protection, explicit risk-acceptance authority and bounded accountability evidence;
- risk, incident and control-catalog foundation workflows;
- verified, non-destructive schema and capability repair;
- expiring advisory security-state requests for File 20/native modules;
- durable, replay-resistant privacy-request orchestration that records metadata before native-module processing;
- truthful privacy aggregation that distinguishes queued or pending work from completed work;
- a private Privacy Requests dashboard for verified-subject dispatch and recent metadata review;
- real File 00 and File 20 detection adapters;
- sanitized private status and public Trust Center REST payloads;
- system checks for WordPress/PHP/HTTPS/schema/debug exposure, public-browsing compatibility, identity, shell, external logs, backup/restore evidence and upgrade errors;
- bounded retention with locks, hold support and failure evidence;
- contract tests, reproducible package tooling, checksums and CI gates.

File 24 does **not** replace File 00 identity, native-module authorization, File 20 shell enforcement, hosting security, a WAF, a SIEM, legal counsel, immutable off-site backup or independent penetration testing.

## Repository safety

This public repository must never contain secrets, live vulnerabilities, forensic evidence, raw personal data, private vendor contracts, backup locations or internal incident playbooks. Those belong in a private security-operations store.

## Development status

The implementation remains on Draft PR #1 and is not production-ready. Local and CI checks do not replace WordPress runtime, Hostinger staging, database upgrade/rollback, backup/restore, accessibility and independent security acceptance.

## Build

```bash
php tests/run.php
php tests/retention.php
php tests/upgrade.php
php tests/findings.php
php tests/runtime.php
php tests/privacy.php
php tests/admin-assets.php
./tools/build-release.sh
```

The package is created under `build/` with a SHA-256 receipt.
