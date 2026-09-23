# File 24 0.99.0 — Module Security SDK and Contracts

A native module integrates by supplying a bounded versioned manifest, canonical owners, data classes, routes, capabilities, vendors, privacy handlers, degraded behavior, release gate, security test time and opaque evidence source. Availability never grants authority.

Shared contracts expose membership/authentication assurance, security-state recommendations, event reporting, privacy export/erase dispatch, evidence adapters and health/posture. Consumers must reject unknown mandatory contract versions and revalidate authorization at action time.


## Canonical full manifest contract

Backward-compatible parsing is retained, but a manifest is **complete** only when the following metadata is explicit in addition to identity/data/routes:

- `tables`, `files`, `secrets` inventories using bounded non-sensitive identifiers;
- `exporters`, `erasers` and `emergency_callbacks`;
- `asvs_level_target` = `ASVS-L2` or `ASVS-L3`;
- explicit numeric `contract_version`;
- `canonical_data_owner` and `canonical_action_owner`;
- opaque `evidence_source`;
- explicit `degraded_behavior` and `release_gate`;
- `last_security_test` when evidence exists.

Missing full-contract metadata is never fabricated. A legacy manifest may remain parseable, but it is normalized to `unassessed` with `manifest_complete=false`; production/high-risk compatibility must therefore remain gated.

## Conditional plan contracts

Traffic Analytics, Disease Intelligence and CF-04 Central Media use `ConditionalIntegrationCatalog`. Repository presence alone does not activate them. Explicit compatible contract version, complete controls, fresh evidence and preserved native ownership are required before an activation request can verify.
