# File 24 — Review and Correction Cycle 39

**Defect:** F24-D073 — Finding transitions lacked complete optimistic concurrency and exact rollback identity.

A same-status edit between read and transition could be overwritten because the update predicate did not bind `updated_at`. Audit rollback matched only UUID and status and could overwrite a newer transition mutation.

## Correction

Finding transitions now require the previously read `updated_at`. Audit rollback is bound to the exact post-write status, update timestamp and governance/acceptance binding. A mismatch creates a durable finding audit gap instead of overwriting newer state.

## Verification

`tests/cycle39-finding-optimistic-concurrency.php` simulates both a same-status version race and a post-transition rollback race.
