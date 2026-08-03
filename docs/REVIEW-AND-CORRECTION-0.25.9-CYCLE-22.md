# Cycle 22 — Manifest Heartbeat Concurrency Review and Correction

**Review mode:** fresh optimistic-concurrency and canonical-identity review  
**Scope:** `ModuleRegistry::persist()`, heartbeat writes, concurrent hash changes and runtime-memory admission

## Defect F24-D056 — zero-row manifest heartbeat treated as success

The 0.25.8 heartbeat path treated every non-error `$wpdb->update()` result as success. A zero-row result can mean that another writer changed the manifest hash between the initial read and the conditional heartbeat update. The old code then admitted the stale incoming manifest into runtime memory despite not proving that storage still contained the same canonical manifest.

## Correction

- heartbeat success now requires exactly one affected row;
- a zero-row heartbeat performs a fresh canonical read;
- only an identical hash with the same immutable module identity is accepted as idempotent success;
- concurrent hash drift fails closed and the manifest is not admitted to runtime memory;
- a dedicated race simulation was added.

## Verification

`tests/cycle22-manifest-heartbeat-race.php` provides six assertions covering concurrent hash drift, runtime-memory exclusion, failure signaling and safe idempotent zero-row behavior.
