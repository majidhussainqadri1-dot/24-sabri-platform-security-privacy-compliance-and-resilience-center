# Review and Correction — Foundation 0.25.2 — Cycle 5

## Review scope

This cycle re-examined the 0.25.1 privacy-request foundation after durable pre-dispatch storage and the private Privacy Requests page were introduced.

## Defects found

1. Queued native work had no bounded completion-callback contract.
2. Request metadata did not preserve per-module outcomes.
3. Failed and partial operations had no controlled retry path.
4. A request could remain `dispatching` indefinitely after process or finalization failure.
5. Retrying an uncertain operation could duplicate export, deletion or correction side effects.
6. Native failure responses did not distinguish safe retry from uncertain post-dispatch failure.
7. The deletion confirmation comparison was not truly case-sensitive.
8. Privacy recovery scheduling and deactivation cleanup were absent.
9. The privacy schema lacked optimistic lock, attempt, retry, error and completion evidence.
10. Generic foundation mocks duplicated privacy behavior and obscured the dedicated workflow tests.

## Corrections

- Upgraded plugin and schema to 0.25.2.
- Added durable per-module result JSON, dispatch attempts, lock version, retry time, error code and completion time.
- Added an atomic module claim before every native handler invocation.
- Added immediate module-result persistence after each native handler returns.
- Left uncertain module evidence as `dispatching`; it is not automatically replayable.
- Added native completion callbacks for pending work.
- Added fail-closed callback rules that prevent completed evidence from being overwritten.
- Added bounded retry for failed, partial and recovery-required requests.
- Limited retry to operations that never started or whose native result explicitly states `retry_safe => true`.
- Added hourly stale-dispatch detection and a recovery-required state without automatic replay.
- Added private retry controls and exact `DISPATCH DELETION` confirmation.
- Added deactivation cleanup for the privacy recovery schedule.
- Split generic foundation and detailed privacy regression coverage.

## Security invariant

A native privacy side effect must never be repeated merely because File 24 lost the final request-level update. Every module operation is claimed before execution. If result persistence is uncertain, File 24 requires reconciliation instead of automatic retry.

## Automated evidence

The cycle includes tests for:

- verified-subject dispatch;
- UUID collision and replay resistance;
- per-module result persistence;
- pending-to-completed native callback;
- completed callback replay rejection;
- explicitly retry-safe failure and bounded retry;
- finalization failure evidence;
- stale-dispatch recovery;
- duplicate-side-effect prevention;
- hourly recovery scheduling and deactivation cleanup;
- all prior retention, upgrade, findings, runtime, asset, secret and package gates.

## Remaining acceptance gates

- real WordPress activation and upgrade against MySQL;
- File 00 native exporter/eraser callbacks on staging;
- File 20 integration;
- accessibility and responsive visual inspection;
- Hostinger staging acceptance;
- backup and restore proof;
- independent security and privacy abuse testing;
- Founder approval.

This document records source-level and automated evidence only. It does not claim production completion.
