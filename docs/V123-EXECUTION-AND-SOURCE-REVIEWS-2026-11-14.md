# File 24 — V12.3 Implementation Execution & Source Review (14 November 2026)

**Classification:** Public-safe technical handoff. **Status:** bounded repository changes implemented; external production release blocked. This is not a live incident resolution.

## 1. Governing documents and scope freeze

- Source of authority: **Sabri Website Master Plan V12.3** (13 November 2026), particularly File 24, `CEN-REL-001`, `F24-CEN-01`, `CV-262..285`, `F24-FUT-001..025`, 12 outcome metrics, QA-15..24, V12.3-01..10, and V12.1-STO-01..10.
- Implementation plan: *Sabri File 24 V12.3 Comprehensive Completion Plan v1.0*, 14 November 2026, stages P0..P9 and handoff D01..D12.
- Existing source candidate is still version `0.99.0`; declared schema `0.25.5`; target production `1.0.0` remains gated.
- `main` baseline at the beginning of this work: `a5b8d49968a7a5a7d6f3f4655bea541bf38a9acb`. The pending source branch is PR #32, `feature/urdu-security-guidance-2026-11-10`; its historical Nov 13 source head was `f9979978b2a65de66e477835180b59164fc7c6e9`.
- Do not infer deployed package/hash, DB schema, migration status, live WAF/MFA or backup health from this branch or from successful CI.

## 2. P0 / P2 work completed in this pass

- Reopened the exact V12.3 plan and code-completion plan; reconciled the split native-owner/assurance boundary.
- Read exact GitHub PR source and CI status, including PHP 8.0/8.3 green at pre-work branch head.
- Wrote `docs/V123-IMPLEMENTATION-RTM-AND-GATES-2026-11-14.md`: 12 metrics M01–M12, 10 QA tests QA-15..24, 10 secure-storage lifecycle checks STO-01..10, 10 V12.3 delta changes = **42 distinct documented IDs**. This is mapping, **not actual staging test completion**.
- Added CI regression `tests/v123-traceability-catalogue.php` ensuring those 42 IDs remain present once, plus mandatory blocked/unverified statuses.
- Added read-only, explicitly authorized private evidence collection helper and guide: `tools/live-reality-freeze-readonly.sh` and `docs/V123-READONLY-LIVE-FREEZE-OPERATOR-GUIDE.md`; CI runs `bash -n`. The helper has **not** been run against a live site.
- Existing cross-module source coverage remains 27/27 in repository contracts; installed cross-file E2E validation has not occurred.

## 3. Bounded source review — distinct passes, NOT independent human approvals

### Pass A — release integrity and waiver semantics

**V12.3-F24-001 (new source finding): waived active release defects.**
- Observation in exact branch source: `ReleaseGateManager::decide` bypassed positive `blockingDefectCount` when `status === waived`, despite CEN-REL-001 requiring zero known defects in the *active* release scope.
- Source correction: all positive gate decisions reject nonzero/invalid active blocker counts, including Founder-governed waivers, while preserving the separate zero-defect residual-risk acceptance mechanism.
- Regression: `tests/v123-release-active-defects-nonwaivable.php`, testing passed/waived/not-applicable rejection and zero-blocker residual-risk waiver.
- Source commit `9d575b5fd89a436df3eaeda136c1281d0638257c`; regression commit `050205b333f275fb6d3b27c4ca0a5e05799743f7`.

**V12.3-F24-002 (new source finding): unknown final blocker providers interpreted as zero.**
- Root cause: WordPress `apply_filters(..., 0)` returns zero when no defect-count provider is registered.
- Source correction: final `24l-independent-assurance-staging` rejects absent P0-count or known-defect-count providers before proceeding; the independent external acceptance flag remains separate. Repository-only internal phases retain historical behavior.
- Regression: `tests/v123-final-release-blocker-provider-required.php`, testing no provider, one provider, both providers without external acceptance, and successful explicit zero+external acceptance.
- Source commit `48df0d5dbb645a781d5854a2da914dc371a5b7c2`; regression commit `d14072082f3d30cce66a7aaba2b897cae401bd91`.
- Limits: a callback being present is not itself proof of authentic producer identity, fresh evidence or production owner sign-off. Those remain actual cross-file integration gates.

### Pass B — false-green and evidence preservation

**V12.3-F24-003 (new source finding): silently discarded malformed/overflowed extension checks.**
- Root cause: `SystemCheck::preserveMandatoryChecks` inspected normalized extension checks, but malformed entries and entries beyond the 100-check bound were discarded before integrity comparison. Required 13 native checks could remain intact and no critical extension-integrity warning would appear.
- Source correction: compare raw filtered item count with normalized bounded count; any loss/truncation emits `system_checks_integrity=critical`, preserving valid warning checks.
- Regression: `tests/v123-system-check-no-silent-loss.php`, covering blank IDs, non-array entries, overflow and valid unknown extension without false positives.
- Source commit `b5ca591bb6162e325f07ebce298b5956e687eb97`; regression commit `920d8263fd4858ae998fd61c8692642abe6b294b`.

### Pass C — multilingual private-data boundary

**V12.3-F24-004 (new source finding): Urdu/Arabic audit-context field values not redacted.**
- The English-only field-name classifier could not interpret a pure Urdu/Arabic key. `Sanitizer::key()` hashed away its label, but the raw textual value survived because it lacked recognizable phone/email/secret patterns, leaking private clinical context to security-event JSON and the event-forwarding hook.
- Source correction: any non-ASCII or wholly unrecognized field name now fails closed at `AuditLogger::redact()` with `[REDACTED]`; familiar bounded ASCII operational labels remain accepted.
- Regression: `tests/v123-multilingual-audit-context-private.php` checks Urdu, Arabic, mixed scripts, nested sensitive values, and safe ordinary metadata. Code correction commit `12a06faae909911a18b66a6affa88564b9e4db32`; test commit `c5c1e1efc492cfc677d13577c614173765dd3f86`.
- This reproduces a **source-level disclosure path**, not evidence that clinical data was actually exposed in production. If installed logs are later examined, handle them privately under authorized retention policy.

### Pass D — reserved diagnostic integrity key

**V12.3-F24-005 (new source finding): forged native integrity-result PASS.**
- The `spcrc/system_checks` extension could append a record named `system_checks_integrity` with `status=pass`; this reserved field was not protected against forgery when the native 13 results were untouched.
- Source correction: reject reserved namespace entries submitted by extensions, preserve the 13 native checks, and create one canonical `system_checks_integrity=critical` incident rather than displaying fabricated success. Ordinary legitimate module checks remain.
- Regression: `tests/v123-reserved-system-check-integrity.php`, added at `d106f2c8c92157e66660fd7b74bad8ddcc00d4fc`; correction in `2db07f4a9f1c18d1154f2b6dd17aab6cb984eb75`.
- This is a bounded source-level integrity finding, not a proven live incident.

### Pass E — V12.3 control semantics and historical evidence tokens

**V12.3-F24-006 (new source finding): obsolete Founder waiver alternative in CV-280 assurance.**
- The prior `ContinuousValueAssurance::REQUIRED['CV-280']` used `zero_known_defect_or_founder_risk_acceptance`, which could mark the two-review release control verified without asserting zero known defects in the active deployment scope. V12.3 `CEN-REL-001` supersedes that rule.
- Source correction: require `zero_known_active_defects`; legacy risk-acceptance label alone fails closed. Residual risks of independently isolated optional features retain separate governance and must not re-enter an active release silently.
- Regression: `tests/v123-cv280-zero-active-defects.php` (historical token blocked, current token verified, both reviews still necessary). Update the former Cycle 112 fixture to test current legal source semantics without rewriting the historical audit record.
- Code commit `8cc2c7ab9aa83388deee82eb04d9940d9ac882e0`, fixture correction `5d4e31896c890da8dfbcb49b25aade17156df945`.

### Pass F — timestamp spoofing in requirement evidence

**V12.3-F24-007: Relative time accepted as a source of freshness.**
- Direct local reproduction against PR HEAD `ee0f4964...`: with all control labels present and an opaque evidence reference, `ContinuousValueAssurance::evaluate('CV-280', ... 'reviewed_at' => 'now')` and `'-3 hours'` both returned `state=verified`. This is a source-level false-green possibility, not a live exposure.
- Root cause: permissive `strtotime()` interprets relative timestamp text; it does not prove an actual recorded human review instant. Correction: use shared strict `Sanitizer::isoTime`, reject ambiguous relative and impossible inputs, preserve explicitly absolute timestamps.
- Source commit `7cadbcd2eecfea8b721cb344e736b807c7898419`, negative regression `tests/v123-cv-evidence-absolute-date.php`.

### Pass G — independent dual-review authenticity

**V12.3-F24-008: Two distinct strings were accepted as two human approvals at final phase.**
- Root cause: `approval_refs` strings were de-duplicated and hashed but did not require a trusted provider to verify actual reviewer identities, review freshness and exact reviewed candidate. A generic artifact with two arbitrary strings could meet this *source* branch of the final decision.
- Correction: phase 24L additionally demands the registered `spcrc/verify_independent_release_reviews` integration. A missing or false provider blocks the final release, retaining generic dual-string requirements only for earlier repository phases.
- Regression `tests/v123-final-independent-review-provenance.php` covers absent, negative and positive simulated trusted provider paths. Test `v123-final-release-blocker-provider-required.php` is adjusted to prove the reviewer gate separately. Actual GitHub human reviews are still **0/2**, not replaced by simulated test fixtures.
- Important trust limit: WordPress filter registration alone is not proof of independent human authorization. The trusted native integration must check actual 2 different human identities, exact artifact SHA, review state and non-expiry; external audit must inspect that provider. This release stays HOLD without it.

### Pass H — canonical source-ID traceability completion

- New exact-source JSON `docs/V123-LEGACY-168-AND-UX14-SOURCE-TRACEABILITY.json`: 100 F24-R, 18 CHAT, 25 CV/CEN, 25 FUT and 14 Master Plan UX journeys. Original four GitHub source-document blob hashes and titles are retained without writing invented Live evidence.
- New `tests/v123-complete-224-id-source-ux-traceability.php` verifies 168+14 plus 42 existing distinct V12.3 IDs = **224/224 source/UX/QA identifiers mapped**. This proves catalogue traceability, not the feature itself.
- Source reviewer cannot claim 100% implementation of 224 runtime journeys from catalogue existence. Native owner and staging/live evidence remain separate.

### Pass I — disaster-recovery evidence freshness

**V12.3-F24-009: Stale historical backup proof could remain green.**
- On the exact pre-patch source, a synthetically supplied `status=verified`, `evidence_ref=vault:...`, backup at -400 days, and later restore at -399 days yielded a `SystemCheck` backup PASS. Both relevant code paths only checked structure, chronology and future-date bounds.
- Source correction: `AssuranceRepository::normalizeBackupEvidence` and `SystemCheck::checkBackupEvidenceAdapter` now require a related successful backup timestamp within 48 hours and associated restore exercise within 93 days (plus prior structural/chronological safeguards). Missing and stale evidence remains non-green.
- New regression `tests/v123-backup-restore-evidence-freshness.php` covers both code paths with past evidence and valid recent pair. Relevant commits `b6f8a4aeb93c1b767a1e81d2ea3c860ffd89b541`, `de08de16cda66fdcc751dd147d4a0ed99b77f494`.
- **Operational boundary:** The status `verified` and opaque reference are still assertions from external providers and human operators, not the actual proof of a successful Hostinger restore; QA-24, G6, RPO/RTO and Founder release approval remain blocked.

### Pass J — audit capacity overflow evidence durability

**V12.3-F24-010: Capacity-failure marker not represented in release health.**
- Reproduction on original PR branch source: a pending `spcrc_audit_gap_capacity_marker` record with `unresolved_count=100` and otherwise empty managed options yielded `SystemCheck audit_gaps=pass`. The marker is an independent indication that a failed mandatory audit-gap write could not be recorded, so its omission could lead to a false-green source release decision.
- Correction: `AuditGapStore::capacityEvidenceUnresolved()` centralizes its read-only presence check. `SystemCheck` reports a critical `capacity-overflow` category; `ReleaseGateManager` prevents a positive decision if marker remains, without dumping any private evidence. This adds no new managed audit-gap domain and retains 17 native option categories.
- Regression: `tests/v123-capacity-marker-release-blocker.php`, detecting a marker-only false green and ensuring an attempted release does not mutate a pending gate.
- Operational limitation: resolution/recovery of a marker requires real private evidence, approved procedure and audit trail. The code does **not** silently delete historical capacity failure.

**Prior historical 11 findings:** preserved in `docs/FILE24-SOURCE-AUDIT-AND-RELEASE-GATES-2026-11-13.md` and its associated tests; not rediscovered or recounted as new defects.

**Cumulative within this bounded PR scope:** 11 pre-existing documented source findings + 10 new V12.3 findings = **21 findings, 21 source corrections proposed and regression tests available.** Final exact-head CI must pass for retest-closed status; no live remediation is asserted.

## 4. Checks and evidence

- Earlier exact-source CI (pre-V12.3): `43350285178` successful on PHP 8.0/8.3 at `f9979978b2a65de66e477835180b59164fc7c6e9`.
- New V12.3 early correction with regression: GitHub run `43552836493` success on PHP 8.0/8.3 at `050205b333f275fb6d3b27c4ca0a5e05799743f7`.
- After each subsequent source/doc change, **verify exact PR-head run under GitHub Actions**. A previous run is not evidence of final HEAD.
- No independent human PR approval is claimed. No staging acceptance, deployed checksum or real backup-restore test was recorded.

## 5. P1 environment blockers actually checked

- Read-only WordPress account site list returned `www.sabrihomeopathy.com` as Jetpack but `site_disconnected`, `site_tools_available=false`.
- WPVibe list had no connected sites. A connection attempt on the known host returned HTTP 530, with no supported diagnosis of the failing hop or live site health.
- **Exact deployed code ابھی unverified ہے؛ repository-based diagnosis provisional ہے۔**
- No public/secrets/private health data was exported to this repository; no production mutation was attempted.

## 6. Remaining mandatory stages and owners

| Gate | State | Required operator/owner action |
|---|---|---|
| G0 — scope/RTM | Working mapping produced | Founder/owners approve active scope and D01 |
| G1 — installed reality | **BLOCKED** | Hostinger authorized read-only package/schema/migration/WP options proof |
| G2 — review pass A | Source fixes proposed; CI evidence at exact source required | Reproducible QA and reviewer disposition |
| G3 — review pass B | Source fixes proposed; **0 independent human approvals** | Two genuinely independent security reviews |
| G4 — merge/build | **NOT DONE** | Authorized PR merge, exact main PHP 8.0/8.3 CI, ZIP/SBOM receipt |
| G5 — staging integration | **NOT DONE** | File 00/02/19/20/CF04 and others actually installed/tested |
| G6 — operational protection | **NOT DONE** | Real WAF/MFA/keys/backup/restore/rollback/alert tests |
| G7 — independent assurance | **NOT DONE** | Authorized pen test, legal applicability, a11y/device acceptance |
| G8 — Founder Go/No-Go | **PENDING** | Active known defects zero and monitored rollback decision |
| G9 — live parity/retest | **NOT DONE** | Deployed byte/schema proof and real smoke tests |

No source-only action can legitimately replace those external receipts or the Founder decision.

## 7. Required five-field production truth

| Field | Current evidence |
|---|---|
| Repository HEAD | Source baseline `a5b8d499...`; new branch HEAD must be re-fetched at close |
| Deployed Version | UNVERIFIED |
| DB Version | UNVERIFIED |
| Migration State | UNVERIFIED |
| Live Verification Status | NOT RUN |

## 8. Defect-accounting discipline

Every subsequent round must report **found / code-fixed / exact-head retested / open / blocked / live-verified**, all separately. Closed GitHub tests do not prove any resolved production vulnerability. Unverified mandatory acceptance is a **release HOLD**, not an evidence-free PASS.

The independent approval gate and real operator-side validation are intentionally unfulfilled in this report. This file records actual bounded progress without claiming completion of a currently inaccessible live system.
