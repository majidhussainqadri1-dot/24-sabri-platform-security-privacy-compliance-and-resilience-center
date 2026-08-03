# Cycle 32 — Audit Evidence Encoding and Write Review

**Review mode:** fresh evidence-loss and exact-write review

## Defect F24-D066

`AuditLogger` silently replaced an unencodable context with `{}` and treated any non-`false` database result—including a zero-row insert—as success. This could create an audit event stripped of required bounded context or claim durability when no row was inserted.

## Correction

- Context encoding failure now returns `spcrc_audit_context_encode_failed` before any database write.
- A canonical security event is accepted only when the insert result is exactly `1`.
- Failure diagnostics remain bounded and exclude the unencodable context.

## Verification

`tests/cycle32-audit-evidence-integrity.php` proves fail-closed encoding, zero-row rejection, no false event append and normal exactly-once success.
