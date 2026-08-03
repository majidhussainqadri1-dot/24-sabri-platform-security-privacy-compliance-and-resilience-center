# Cycle 19 — Privacy Retry Safety Review and Correction

**Review mode:** fresh destructive-operation, retry-idempotency and storage-boundary audit
**Scope:** canonical privacy retry claims, module evidence preservation, operator identity and replay prevention

## Defect F24-D053 — storage-layer bypass of safe-retry policy

The public privacy policy layer required a `retry-safe-` module code before replaying a failed native-module operation. The canonical storage repository, however, reset every failed, rejected, unavailable or recovery-required module when `claimRetry()` was called directly. An internal caller could therefore bypass the higher policy layer and replay a deletion/export/provider operation whose outcome was uncertain.

That contradicted the plan's fail-closed, privacy-rights, idempotency and duplicate-side-effect requirements.

## Correction

- made the storage repository independently enforce the canonical `retry-safe-` evidence prefix;
- retained unconditional retry only for modules that never started;
- preserved uncertain failed/recovery evidence without resetting or replaying it;
- kept completed, pending and dispatching module evidence immutable;
- rejected retry claims with no provably safe module;
- required a valid WordPress operator at the storage boundary;
- added `tests/cycle19-privacy-retry-safety.php` with functional state and source-contract assertions.

## Review result after correction

The retry invariant now exists at both the policy and storage boundaries. A caller cannot obtain a destructive-operation replay merely by bypassing the dispatcher. Only never-started modules or failures explicitly marked safe before side effects are returned to `not-started`; all uncertain evidence remains intact for reconciliation.
