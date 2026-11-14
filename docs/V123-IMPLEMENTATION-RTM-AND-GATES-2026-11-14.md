# File 24 — V12.3 source-to-acceptance traceability (initial P2 inventory)

**Status: Source-audit working baseline, NOT staging/production acceptance.** Updated 14 November 2026. Governing source: *Sabri Website Master Plan V12.3*, chapters 1, 3, 8, 9, 11 and 12, and File-24 completion plan v1.0.

## Frozen source identities (three realities)

- Base `main`: `a5b8d49968a7a5a7d6f3f4655bea541bf38a9acb` as observed before V12.3 implementation changes. Recheck HEAD on every future run.
- Existing PR #32 before this V12.3 correction: `f9979978b2a65de66e477835180b59164fc7c6e9`.
- Code candidate: `0.99.0`; source-declared schema: `0.25.5`; production target `1.0.0` **not yet approved**.
- Installed/production plugin version/hash, actual schema/DB/version, migration state, active WAF/MFA, backup/restore, live smoke test: **UNVERIFIED**.
- **Do not substitute prior source QA or source schema metadata for actual Hostinger/WordPress reality.**

## Original requirement families (source candidate only)

| Family | Count | Source record | Present evidence | External state |
|---|---:|---|---|---|
| F24-R001..F24-R100 | 100 | Requirements traceability | Repository-marked implemented | Real integration pending |
| 18 CHAT-* directives | 18 | CHAT directives traceability | Repository-marked implemented | Actual effects pending |
| CV-262..CV-285 + F24-CEN-01 | 25 | Continuous Value RTM | 25 source/evidence contracts | Provider/owner evidence pending |
| F24-FUT-001..F24-FUT-025 | 25 | Future Security Superset | 25 repository contracts | Real provider/equipment evidence pending |
| Files 00–26 | 27 | Integration matrix | Source contract inventory | Installed modules unverified |
| CF-04 / Traffic Analytics / Disease Intelligence | 3 | Conditional contracts | Source contract inventory | Real activation unverified |

*168 is a historical requirement-family count, not percentage complete under V12.3 and not independent operational certification. Cross-family mappings must not be double counted.*

## V12.3 twelve cross-platform outcome metrics

|ID|Outcome|Native owner|File 24 role|Acceptance evidence pending|
|---|---|---|---|---|
|M01|Web/browser functionality|File 20 + File 25|File 24 QA|320/390/768/1024/1440; JS-off; RTL; keyboard|
|M02|Complete accessibility|File 20/25|File 24 QA|WCAG 2.2 AA, assistive technology, 200/400% zoom|
|M03|Performance|Native route owner + CF 05|File 24 PerformanceMonitor|Lab and field p75 with sample/window; no false field status|
|M04|Translation/search|CF 06 + File 26|File 24 assurance|Source edition, rights, hreflang, withdrawal|
|M05|Scientific provenance|File 21/22/23 + source owners|File 24 assurance|Author/source/review/correction/rights evidence|
|M06|Authentication and recovery|File 00/02|File 24 assurance|Passkey, session revocation, privileged MFA, actual recovery|
|M07|Personal information|Native data owners|File 24 privacy assurance|Consent, purpose, export/delete/hold, provider limits|
|M08|Clinical and AI safety|CF 01 + File 16/AI owner|File 24 assurance|Source, uncertainty, clinician authority, escalation|
|M09|Messaging/media|File 19 + CF 04 and media owners|File 24 assurance|State, scan, resumption, revocation, text fallback|
|M10|Offline safety|File 20 + owner|File 24 assurance|Public-only cache, logout/revoke, browser fallback|
|M11|Safe release|File 01 B + deploy owner|File 24 independent evidence|Version, migration, restore, rollback, live retest|
|M12|Free-tier fairness|Donations/marketplace owner|File 24 governance assurance|No paid priority, 0% commission, genuine ledger|

**Disposition:** 12/12 owner-and-acceptance lines inventoried; 0/12 freshly verified in production. Source implementation of each cross-file outcome has **not** yet been independently confirmed; do not mark coded solely because the target code is named.

## V12.3 mandatory new acceptance tests

|ID|Task under test|Required independent evidence|Actual status|
|---|---|---|---|
|QA-15|Browser responsive functional journeys|320–1440px, JS-off, assistive modes, RTL|NOT RUN on deployed/staging build|
|QA-16|WCAG 2.2 AA full task|Keyboard/screen-reader/zoom/reflow/forced-colors/reduced-motion|NOT RUN on deployed/staging build|
|QA-17|Lab vs field performance|P75 window/samples, low-end devices and route budgets|NOT RUN on deployed/staging build|
|QA-18|Source and version retraction|Canonical, search, translation, AI references, no private leak|NOT RUN on deployed/staging build|
|QA-19|Actual identity enforcement|Recoveries, role/guardian/revoked sessions|NOT RUN on deployed/staging build|
|QA-20|Privacy request completion|Synthetic consent/export/delete/hold, cache/index/backup receipt|NOT RUN on deployed/staging build|
|QA-21|Clinical and AI boundaries|Authority, uncertainty, emergency and external provider failure|NOT RUN on deployed/staging build|
|QA-22|Messaging/media/offline resilience|Two devices, permission revocation, retries, logout|NOT RUN on deployed/staging build|
|QA-23|Publishing and payment fairness|Native editorial hold; no donation advantage or duplicate charge|NOT RUN on deployed/staging build|
|QA-24|Release and recovery|Exact package/schema, isolated restore, controlled live parity|NOT RUN on deployed/staging build|

**Disposition:** 10/10 test definitions mapped; 10/10 actual staging/live acceptance receipts outstanding.

## Storage and secure-media lifecycle: cross-owner assurance, not new File-24 datastore

|ID|Boundary|Enforcement owner|Real integration evidence required|
|---|---|---|---|
|STO-01|Upload-intent authorization|CF 04|User, purpose, privacy, consent, quota, server-side check|
|STO-02|Private quarantine and resumable chunks|CF 04|Session-bound TTL and no early public delivery|
|STO-03|Malware/media scanner fail-closed|CF 04|MIME, magic, scanners, malicious file negative cases|
|STO-04|Sandbox derivative generation|CF 04|Isolated preview/OCR/transcode, EXIF policy|
|STO-05|Protected object and key receipt|CF 04 / host|At-rest encryption/key lifecycle/hash, no secrets in log|
|STO-06|Canonical state machine|CF 04 / native domain|Pending/Quarantined/Scanned/Ready/Rejected; retries|
|STO-07|Private authenticated download|CF 04 / owner|Revoke/session/object auth at each private request|
|STO-08|Integrity, orphans and cost|CF 04 / operations|Hash/corruption/orphan detection, quota, alerts|
|STO-09|Delete and CDN/derivative purge|CF 04 + data owners|Tombstones, holds, expiration, revoke receipts|
|STO-10|Restore and export portability|CF 04 + operations|Restored permissions/tombstones and checksums|

**Disposition:** 10/10 assurance-contract checkpoints mapped, 0/10 Hostinger-like CF-04 end-to-end validation receipts currently available.

## V12.3 additional change controls

|ID|Subject|Canonical parties|Observed status|
|---|---|---|---|
|V12.3-01|Distinct formative/user-acceptance samples|File 20/25 + File 24|Evidence pending|
|V12.3-02|Browser/accessibility coverage|File 20/25 + File 24|Evidence pending|
|V12.3-03|Production performance truth|CF 05 + File 24|Evidence pending|
|V12.3-04|Knowledge/source provenance|Content owners + File 24|Cross-file evidence pending|
|V12.3-05|Account safety and personal-data rights|Files 00/02 + File 24|Cross-file evidence pending|
|V12.3-06|AI/clinic safety and escalation|AI/clinic owners + File 24|Cross-file evidence pending|
|V12.3-07|Offline/install access boundaries|File 20 + File 24|Cross-file evidence pending|
|V12.3-08|Release/recovery/rollback|File 01 B + File 24|External proof pending|
|V12.3-09|Locale target/reserve decisions|CF 06 + Founder|Founder decisions pending|
|V12.3-10|Truthful 12 metrics/10 QA/active scope|File 01 + File 24|RTM drafted; acceptance pending|

## Current source review and defect register

- PR #32 historically records **11 source defects with 11 source corrections**, CI green at its earlier exact PR head on PHP 8.0 and 8.3. This is not live remediation.
- **V12.3-F24-001 (new finding): active release-defect waiver bypass.** Root cause in `ReleaseGateManager::decide`: a conditional `$status !== 'waived'` skipped the known active `blockingDefectCount` check for waived gates. Master Plan `CEN-REL-001` explicitly requires zero known unresolved defects in the active release scope; founder risk acceptance is not a bypass for such defects.
- Source correction on PR #32: reject positive gate decisions with active unresolved defect counts, including `waived`; retain a separately governed residual-risk waiver only when active defect count is zero, or when a disabled optional feature is proven isolated and excluded from active scope by its native owner.
- Regression: `tests/v123-release-active-defects-nonwaivable.php`. Exact updated commit CI must still be verified. **15 source-level findings recorded cumulatively in this bounded PR audit, 15 code corrections proposed, not 15 live resolved bugs.**
- **V12.3-F24-002 (new finding): missing final release blocker-count providers could appear as verified zero.** WordPress `apply_filters('spcrc/release_blocking_p0_count', 0,...)` and `apply_filters('spcrc/release_blocking_defect_count', 0,...)` return zero when no provider is registered. The final phase `24l-independent-assurance-staging` can no longer use missing-provider default zeros to declare a known-defect-free scope. It now fails with `spcrc_release_gate_blocker_provider_missing` unless both hooks have a registered provider. Distinct external-staging readiness remains an additional gate; internal repository-only phases retain their historical behavior. Regression: `tests/v123-final-release-blocker-provider-required.php`.
- **V12.3-F24-003 (new finding): silently discarded malformed/overflowed extension checks.** `SystemCheck::preserveMandatoryChecks()` normalized externally appended checks before checking their integrity; invalid records, blank identifiers, non-array entries, or data beyond its 100-item cap were dropped with no `system_checks_integrity` result as long as the native 13 checks survived. The fix compares raw filtered record count against the bounded normalized count; loss or truncation produces a critical integrity finding while retaining valid extension warnings. Regression: `tests/v123-system-check-no-silent-loss.php`.
- **V12.3-F24-004 (new finding): Unicode field-name disclosure in audit context.** `AuditLogger::redact()` checked known English field names, then generated a harmless-looking hashed key for an all-Urdu or all-Arabic label. A value containing no detectable secret pattern (e.g., the patient's narrative) could be saved in cleartext under the hashed key. Source correction: all unrecognized or non-ASCII field names fail closed with `[REDACTED]`; safe known ASCII diagnostic keys remain visible. Regression: `tests/v123-multilingual-audit-context-private.php` covers Urdu, Arabic, mixed-language, and nested medical narratives.
- **Current bounded cumulative source register: 15 findings / 15 source corrections proposed**, comprising 11 historical PR #32 source defects and V12.3-F24-001 through -004. These changes are NOT production remediation. Exact latest PR-head CI and independent reviews remain separate.
- **Residual design risk:** a registered callback alone does not prove that the callback is the authentic native owner or the evidence is current. Provider provenance, owner assertion, and deployed parity remain production acceptance requirements and may require additional bounded work after cross-file contracts are available.

## Work products and independent gates

| Deliverable | Current disposition | Completion criterion |
|---|---|---|
| D01 Scope and Requirement Freeze | This mapping is a working baseline; Founder sign-off pending | All active requirements linked to owner/source/test/evidence |
| D02 Real environment inventory | BLOCKED / unavailable | Read-only deployed version, checksum, wp_options, tables, migrations |
| D03 Deployment parity | BLOCKED until D02 | Exact source/package vs installed bytes/schema |
| D04 Two reviews | First bounded source corrective pass only; **zero human approvals** | Two genuinely independent reviewers, each with dispositions |
| D05 Exact main release receipt | NOT READY | Authorized merge plus exact main PHP 8.0/8.3, deterministic ZIP/SBOM |
| D06 Cross-file integration | Source 27/27 contracts only | Real enabled owner runtime contracts tested |
| D07 UX/QA evidence pack | NOT RUN externally | QA-15..24 and UX journeys as appropriate in staging/live |
| D08 CF04 storage assurance | BLOCKED on real CF04 | STO-01..10 with signed/opaque receipts |
| D09 Independent legal/security/a11y | NOT COMPLETED | Professional assessment, mitigations, independent retest |
| D10 Recovery/incident drills | NOT COMPLETED | Real isolated restore, rollback and incident rehearsal |
| D11 Founder Go/No-Go | PENDING | Zero active known defects, full release evidence, safe fallback |
| D12 Live deployment/retest | NOT COMPLETED | Deploy checksum, DB state, access, rollback and monitoring receipts |

## Production incident fields (mandatory)

`Repository HEAD` = read at incident time;
`Deployed Version` = UNVERIFIED;
`DB Version` = UNVERIFIED;
`Migration State` = UNVERIFIED;
`Live Verification Status` = NOT RUN.

**Exact deployed code ابھی unverified ہے؛ repository-based diagnosis provisional ہے۔**

## Next gate

Review `V12.3-F24-001` with exact PR-head CI and two independent humans; run a fresh gap audit on installed owners and environments. Do not merge, deploy, or mark operational until the required gates pass.
