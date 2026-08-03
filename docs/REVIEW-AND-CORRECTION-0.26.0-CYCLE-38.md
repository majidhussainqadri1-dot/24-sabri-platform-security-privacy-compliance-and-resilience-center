# File 24 — Review and Correction Cycle 38

**Defect:** F24-D072 — Risk acceptance lacked complete optimistic concurrency and exact rollback identity.

A same-status concurrent edit could be overwritten because the acceptance predicate checked only UUID and status. On audit failure, rollback also matched only the accepted status and could overwrite a newer accepted-row mutation.

## Correction

Acceptance now binds the previously read `updated_at` value. Audit rollback is bound to the complete post-write identity: accepted status, treatment, governance decision, accepting user, acceptance timestamps and update timestamp. A mismatched rollback creates a durable audit gap rather than clobbering newer state.

## Verification

`tests/cycle38-risk-optimistic-concurrency.php` proves same-status edit rejection and proves that audit rollback cannot overwrite a concurrently changed accepted row.
