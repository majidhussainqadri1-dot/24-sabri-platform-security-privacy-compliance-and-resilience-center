# File 24 — Fresh Adversarial Review and Correction — Continuous Value Round 2

## Adversarial focus

The second independent review attacked the corrected current-plan implementation through unknown requirement identifiers, incomplete evidence, unsafe references, stale/unparseable review time, fail-open degradation, incomplete progressive delivery, vendor lock-in and architectural ownership violations.

## Cases enforced

- unknown `CV-*` identifiers must be `unknown` and fail closed;
- missing consent withdrawal blocks CV-268;
- path-like/traversal evidence references are rejected;
- invalid review timestamps cannot produce verified status;
- graceful degradation without an explicit `no_security_fail_open` guarantee blocks CV-277;
- a release process missing the canary ring blocks CV-279;
- vendor resilience without an exit plan blocks CV-284;
- File 24 native-control takeover blocks `F24-CEN-01`;
- making File 24 a security single point of failure blocks activation;
- exposing private operations material blocks activation;
- omitting native validation from preserved native controls blocks activation;
- every CV record must retain a bounded canonical owner and must not silently become File-24 native truth.

## Corrections after adversarial review

The assurance evaluators were kept deliberately fail-closed: only complete required control sets with an opaque evidence reference and valid review time can reach `verified`; the Assurance Center cannot activate when ownership, private-operations or single-point-of-failure invariants are violated. The requirement catalogue preserves external-evidence mode for requirements that cannot truthfully be proven by repository code alone.

The first exact-head PR run also exposed one **pre-existing latent QA defect** outside the new CV classes: `tests/privacy.php` had a hard-coded 31 July verification timestamp while production correctly limits manual privacy-verification evidence to seven days. On 8 August that fixture became stale, causing the historical privacy suite to fail even though the production freshness control was behaving correctly. The defect was corrected in the test fixture by generating a verification timestamp one minute before execution. The seven-day production freshness gate was preserved unchanged. This converts a calendar-dependent regression into a deterministic security test instead of weakening security to make the test pass.

## Retest and closure

Cycle 113 encodes the new Continuous Value negative paths as permanent regressions. The complete historical suite is then rerun on the corrected exact head, including the repaired privacy regression. Combined with Cycle 112, this satisfies the later two-review law at repository level: fresh review → correction → retest → fresh adversarial review → correction → exact-head retest.

**Repository result:** closure is accepted only when the corrected exact-head CI is green on both PHP 8.0 and PHP 8.3, deterministic packaging succeeds and no known repository defect remains. Hostinger staging, real providers, independent penetration testing, qualified legal review, restore drills, browser/accessibility acceptance, live deployment and operational SLO evidence remain separate gates and are not claimed here.
