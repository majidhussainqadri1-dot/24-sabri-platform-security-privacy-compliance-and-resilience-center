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

## Second independent-from-history source pass — 13 November 2026

This additional analytical pass reviewed the actual PR branch code, rather than treating earlier CI or the historical 280 correction cycles as fresh assurance.

| Finding | Reproduced root cause | Implemented source correction | Executable regression |
|---|---|---|---|
| S-2026-11-13-03 — Base system-check suppression and false green | `SystemCheck::run()` accepted the whole externally filtered result. Reproduction: a `spcrc/system_checks` filter returning only one fabricated green record removed all 13 native checks. | Preserve all native results independently, permit legitimate appended checks, and emit `system_checks_integrity=critical` if any required check is missing, duplicated or changed. | `tests/system-check-integrity.php` |
| S-2026-11-13-04 — Operational gap categories omitted from status | `SystemCheck::checkAuditGaps()` maintained only an inline 14-category subset, while `AuditGapStore::managedOptions()` included detection, remote evidence and deletion replay (17 managed categories). Thus real gaps could coexist with `audit_gaps=pass`. | Use canonical `AuditGapStore::managedOptions()` and `AuditGapStore::count()` for every category. Updated historical Cycle 16 source assertion to validate the authoritative registry contract rather than stale inline text. | `tests/system-check-audit-gap-coverage.php`, `tests/cycle16-closure.php` |
| S-2026-11-13-05 — Corrupt audit-gap evidence reported as absent | `AuditGapStore::count()` normalized an invalid nonempty persisted record down to zero. Demonstrated with a nested row missing a `reason`: raw 1, normalized 0, reported 0. | An unrecognized nonempty persisted audit-gap state now counts as at least one unresolved blocker. Release and status paths must not falsely report clean. | `tests/audit-gap-corrupt-evidence.php` |

The second pass discovered **three distinct source root causes**. Including the original draft's three guidance/CI defects and the earlier 13-November two root causes, PR #32 contains **8/8 code-corrected source findings**. The tests cover expected-failure, allowed-extension, legacy and corrupt-evidence scenarios. There is no claim of eight confirmed live defects.

### Verification — second pass

- Exact PR-head GitHub Actions at the code-correction commit `f607b44d1c488edbdee5ce7644a7aedd69fab5c7`, Run `43345358710`: **PHP 8.0 and PHP 8.3 jobs both successful**.
- Separate local PHP 8.4 validation: **305 PHP source/test files syntax-checked; 213/213 independent top-level tests passed** after updating the historical Cycle 16 assertion.
- The executable plugin ZIP was built deterministically and compared **byte-for-byte** to the exact-commit GitHub Actions package. The verified inner installable plugin ZIP SHA-256 was `e55e5b8dcb6148d342ebb4a501a0fafe29616530d610952fdfc6f7fd7363625f` at that code-correction commit.
- Independent human security reviews are not yet recorded as approvals. Do not merge solely because code-level review and CI are green.
- No deployment, staging acceptance, backup verification or live database/schema inspection was possible through disconnected WordPress/Jetpack access.
- Deployment-Parity Audit is mandatory before any installation. Unknown live versions/migrations are explicit blockers, not reasons to create speculative live patches.

### Defect disposition — no false closure

| Measure | Count |
|---|---:|
| PR #32 source root causes recorded (earlier + this pass) | 8 |
| Source fixes implemented with regression evidence | 8 |
| Outstanding **known** source defects in this bounded audited set after QA | 0 |
| Independent human reviewers recorded for the latest code | 0 |
| Live-deployed or live-retested fixes | 0 — deployment unverified |
| External acceptance gates | open; do not report 100% production completion |


## Additional private-evidence boundary correction — 13 November

**Finding S-2026-11-13-06 — Clinical PII in audit-gap metadata.** A reproducible test invoked `AuditGapStore::record(..., ['patientName'=>'PRIVATE PERSON', 'medicalHistory'=>'PRIVATE HEALTH NARRATIVE'])`. The existing `safeContext()` normalized those camelCase identifiers but persisted their plain-text values because its sensitive-field pattern only recognized some delimited names. The legacy read-normalizer had the same omission.

**Fix:** `AuditGapStore::sensitiveContextKey()` now classifies compact normalized identifiers for identity, patient, guardian, clinical notes, history, diagnosis, symptoms, contact and secret fields. Both the write-side `safeContext()` and the read-side `normalize()` redact those keys. A previously stored record is not silently rewritten; the read projection protects disclosure while an authorized archival/retention process handles existing data. Source program `tests/audit-gap-sensitive-field-aliases.php` proves before-storage redaction, legacy-read masking and retention of innocuous bounded metadata.

**Source QA:** at correction HEAD `57233ebe5d7645657384d8ef6bbc190205fabb9d`, exact PR-head CI Run `43346497766` passed PHP 8.0 and PHP 8.3. Separately executed PHP 8.4 checks: **306 PHP files lint-clean and 214/214 top-level test programs passed**. The deterministic installable ZIP was byte-identical between the GitHub Actions artifact and a local rebuild; its SHA-256: `d9cc7ab2ec965efa7f3538889f35e6bc3f285904988b4454bf32510d8ead2d65`.

**Cumulative reviewed PR finding register:** pre-existing three + earlier two 13-Nov + next three + this additional one = **9 source defects located and 9 source corrections/test regressions present**. No live-scope or staging resolved claim follows. External gates remain unaffected and mandatory.

## Trust Center publication-window safety — further source correction

**Finding S-2026-11-13-07 — Trust Center scheduled publication bypass:** a draft approved for future public availability could be silently turned into an immediately effective claim. Reproduction: create a draft with `effective_at = now + 1 hour`, then approve the claim without `effective_at`; `TrustCenterService::saveClaim()` previously stored the approved record with no effective date and `publicClaims()` immediately returned it.

**Root cause:** verified-claim authorization protected content/editor separation and evidence windows but did not require a nonempty draft's separately authored effective timestamp to match the approval's effective timestamp.

**Source fix:** preserve the original independently authored effective time at verification; omitting or changing that date fails with `spcrc_trust_claim_effective_window_changed`. Legitimate approval with an exactly matching schedule remains available, and future-effective claims do not publicly publish early.

**Permanent regression:** `tests/trust-approval-effective-window.php` covers omission, attempted advance, nonpublication, and legitimate matching-time approval, while historical Cycle 109 remains intact.

**QA:** code HEAD `df64667c512e5d37c78588c2d4ae8b4d50a1c621`; GitHub Actions Run `43347647625` passed PHP 8.0 and 8.3. Local PHP 8.4 validation: 307 PHP source/test files lint-clean; **215/215** top-level regression tests PASS. Deterministic installable ZIP byte-identical with GitHub Actions artifact; SHA-256 `cda925d5b4f9b74665d098f9becff16e408b2270c3ed5f8382b853b31db333c0`.

**Cumulative PR #32 finding count:** 3 original + 2 initial 13-Nov + 3 operational truth + 1 AuditGapStore PII + 1 Trust Center schedule = **10 source defects found, 10 code corrections and tests present**. This remains source-only; independent reviewers, merge, exact-main CI, Hostinger staging, DB/schema parity, backups/restore and live acceptance are still unverified.
