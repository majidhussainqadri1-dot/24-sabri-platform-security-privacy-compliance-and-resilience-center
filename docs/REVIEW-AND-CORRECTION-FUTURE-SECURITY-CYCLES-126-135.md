# File 24 — Ten Fresh Review / Correction Rounds — Cycles 126–135

## Governing boundary

These ten rounds re-open the exact `main` source after Cycle 125 and test the current File 24 repository against the governing requirement chain: base `F24-R001..R100`, recovered `CHAT-*`, `CV-262..CV-285`, `F24-CEN-01`, `F24-FUT-001..025`, native-owner preservation, fail-closed security, evidence freshness, privacy-by-default, lifecycle integrity, concurrency safety and truthful seven-status release reporting.

This is repository-coding/automated-QA assurance. Hostinger staging, live providers, independent penetration testing, legal applicability, restore drills, production deployment and operational SLO evidence remain separate gates.

## Final count

| Item | Result |
|---|---:|
| Fresh review rounds | **10** |
| Defect-bearing rounds | **10** |
| Clean rounds | **0** |
| Defect-bearing cycles | **126, 127, 128, 129, 130, 131, 132, 133, 134, 135** |
| Known unresolved repository-correctable defects after fixes/retests | **0** |

## Round register

| Cycle | Review focus | Defect found | Correction / permanent retest |
|---:|---|---|---|
| 126 | Truthful release-scope parity | `ReleaseStatus` and `CompletionCheck` could declare repository completion without explicitly gating the later 25 CV/CEN requirements and 25 Future capabilities. | Release truth now requires base + CHAT + CV/CEN + Future catalogue completion and exact Future assurance-ID parity; System Check exposes both later-scope gates. |
| 127 | Boundary-policy evidence freshness | Complete but years-old boundary evidence could remain `verified` and `write_allowed`. | Boundary evidence has bounded freshness, future-date rejection and explicit `evidence_fresh` state. |
| 128 | Vulnerability lifecycle integrity | A vulnerability could jump from `reported` directly to `remediated`/later states because only target status/evidence was checked. | Explicit state-transition graph, mandatory lifecycle evidence, high/critical containment-before-remediation and verify/retest-before-close gates. |
| 129 | Annual governance review expiry | An annual review pair from 2020 could still validate because only interval length was checked. | Reviewed-at cannot be materially future; next-review must still be in the future; Anti-Surveillance inherits the same current-window gate. |
| 130 | AI Teacher launch and evidence time | A future launch date (and stale test evidence) could still authorize institutional AI publication. | Launch must be current/non-future, test evidence must be fresh, and first-30-day human review remains mandatory. |
| 131 | Performance evidence integrity | Tampered `INF`/`NaN` values and mixed units could be aggregated into a measured p95/max. | Read-time finite/non-negative validation, canonical unit selection, mixed-unit exclusion and record-time unit consistency. |
| 132 | Transfer/download evidence freshness | Complete transfer/download control lists with years-old/future `tested_at` could remain verified. | Both assurance paths now require bounded fresh, non-future test evidence. |
| 133 | Upload scan binding | A clean scanner result was not cryptographically bound to the exact quarantined SHA-256 and scan freshness was not enforced. | Scanner contract requires exact expected/source SHA-256 equality and fresh scan time before a clean result may permit delivery. |
| 134 | One-time private-delivery concurrency | `consume()` used read-modify-write without an atomic per-grant lease, allowing a concurrent double-consume window. | Per-grant `AtomicOptionLock` serializes consumption; contention fails closed; durable consumed-state/replay rules remain. |
| 135 | Same-origin port semantics | `sameOriginUrl()` compared only HTTPS + host, so `https://example.test:4443` was incorrectly treated as the home origin. | Home/target scheme and effective port must match; credentials remain forbidden. |

## Permanent regressions

`tests/cycle126-*` through `tests/cycle135-*` are ten independent top-level regression programs. Historical tests were strengthened where the corrected contract intentionally changed: Cycle 98 scan binding; Cycle 99 vulnerability lifecycle; Cycles 110–111 deterministic review/evidence-time contracts.

Local full-suite verification after the corrections: **227 PHP files lint-clean and 140 independent top-level PHP tests passing** on the available review runtime. Exact-head GitHub Actions must still pass PHP 8.0 and PHP 8.3 before merge.

## Stop condition

The requested ten-round repository review stops only at zero known unresolved repository-correctable defect in the reviewed scope. Any later CI failure, staging discrepancy, provider behavior, dependency change, security advisory or user evidence re-opens review.
