# File 24 — Source-security audit, corrections, and remaining release gates — 13 November 2026

## Authoritative scope and truth boundary

This record concerns repository **source only** for File 24, alongside Sabri Central Master Plan V12.1, its seven-point Urdu cybersecurity policy, and the approved no-P0-defect release principle.

- Frozen default-branch HEAD before this session: `a5b8d49968a7a5a7d6f3f4655bea541bf38a9acb`.
- Existing educational guidance draft PR #32 before these corrections: `f4c70d0fa11c974e9f90ba9a9d96b67ccce51611`.
- Current review branch: `feature/urdu-security-guidance-2026-11-10`.
- Candidate runtime: `0.99.0`; declared source schema: `0.25.5`.
- Source scope implemented before this review: F24-R001–100 (100), CHAT directives (18), CV/CEN (25), Future Security Superset (25), and Files 00–26 integration contracts (27).
- Repository ZIP, staging, deployed WordPress files, live database and operational controls are **different evidence sources**.

This audit does **not** establish that the candidate is deployed, externally certified, legally compliant in every jurisdiction, or that any real WAF, MFA, backup, independent penetration test, or restore rehearsal is operational.

## Source defects and corrections

| Finding | Evidence and root cause | Correction | Regression |
|---|---|---|---|
| S-2026-11-13-01 — PII alias leak in audit context | `AuditLogger::redact()` blocked some known snake_case identifiers but did not classify several camelCase patient names, case-history and narrative keys; simple free-text patient values may contain no pattern detected by `containsSensitiveMaterial()`. | Normalize compact field names and redact known clinical narrative/identity aliases; pseudonymize common camelCase contact, IP and device identifiers. | `tests/audit-sensitive-field-aliases.php` |
| S-2026-11-13-02 — P0 gate waiver | `ReleaseGateManager::decide()` previously enforced `spcrc/release_blocking_p0_count` only where status was not `waived`, even though a P0 safety/security defect must not be made acceptable through a waiver. | A positive gate decision, including a Founder-governed waiver, fails closed for any P0 blocker or invalid P0-count evidence. Noncritical governed-waiver evidence chain remains available. | `tests/release-p0-nonwaivable.php`, alongside historical `tests/cycle171-release-waiver-evidence-chain-review.php` |

Three earlier defects in the pending PR #32 (dynamic shortcode stylesheet, duplicate ARIA IDs, and exact PR-head CI checkout) were already corrected in that draft before this audit. Do not double-count them as new 13-November discoveries.

## Verification contract

1. Run all PHP syntax checks and all top-level PHP regression tests on PHP 8.0 and PHP 8.3, including the two new programs and the earlier guidance test.
2. Verify checked-out commit SHA equals the PR head SHA, not GitHub's synthetic merge ref.
3. Verify source checksum ledger, deterministic ZIP build, artifact checksum receipt, SBOM, requirements and 27/27 integration matrix.
4. After repository review and authorized merge, repeat the entire exact-main CI. Do not infer a green main from green PR CI.
5. Before any Staging installation: freeze the active WordPress/plugin versions, DB/schema, wp_options and migration state; backup and verify installed-code parity.
6. On Staging: run negative-role, upload quarantine, private-object authorization, registration/recovery, File 00/02/20 integration, RTL/keyboard/zoom, backup restore and rollback drills.
7. External approval: independent code/security assessment, applicable legal/privacy review and explicit Founder staging decision.
8. Production: staged rollout with verified backups, monitored impact, exact deployed checksum, real user journey re-test and complete defect register.
9. Mark a defect **Resolved Live** only on fresh, matching production evidence. Repository-fixed is a distinct status.

## Current external evidence gaps

- WordPress.com/Jetpack site-specific connection currently reports `site_disconnected`; WPVibe has no registered connection and its attempted connection returned HTTP 530. Those are **access blockers**, not proof that the live site is down or compromised.
- Installed File 24 version and exact code hash: unverified.
- Production DB version, table/index integrity and migration state: unverified.
- Hostinger WAF/DDoS/TLS/MFA settings: unverified.
- CF-04 private object-store delivery and clinician authorization: unverified.
- Real backup restore, rollback, independent pentest, legal and accessibility acceptance: unverified.

**Required incident truth fields:** Repository HEAD / Deployed Version / DB Version / Migration State / Live Verification Status. Where deployed source cannot be read, state: “Exact deployed code ابھی unverified ہے؛ repository-based diagnosis provisional ہے۔”

## Completion-status vocabulary

- `specified`: repository scope and requirements mapped
- `coded`: source candidate with tests
- `packaged`: exact commit and ZIP/checksum verified
- `automated_qa_green`: immutable exact-head CI evidence
- `staging_accepted`: actual staging installed, integration/restore/rollback tests accepted
- `live_deployed`: exact deployed version/hash verified
- `operational`: real production controls, alerts and SLO evidence accepted

Never elevate one status to another without its own evidence.
