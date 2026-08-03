# Sabri Platform Security, Privacy, Compliance and Resilience Center

File 24 is the central security-governance and assurance plane for the Sabri Social Homeopathy Platform. Native modules retain authentication, authorization and canonical data ownership.

## Foundation scope — forty-round corrective candidate 0.28.0

This reviewed Foundation establishes and re-verifies:

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

The 0.28.0 implementation is a reviewed Foundation candidate and is not production-ready. Automated checks do not replace real WordPress/MySQL activation, migration and rollback, Hostinger staging, live File 00/File 20 integration, accessibility/browser acceptance, restore drills, provider validation, abuse testing, legal review or independent penetration testing.

## Build and QA

```bash
find plugin tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l
while IFS= read -r -d '' test_file; do php "$test_file"; done < <(find tests -maxdepth 1 -type f -name '*.php' ! -name 'bootstrap.php' -print0 | sort -z)
./tools/build-release.sh
```

The installable package and SHA-256 receipt are created under `build/`.
