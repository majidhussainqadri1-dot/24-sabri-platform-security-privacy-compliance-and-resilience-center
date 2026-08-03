# Cycle 21 — Complete Schema and Release Closure Review and Correction

**Review mode:** fourth fresh review; schema-integrity, uninstall, release-parity and evidence-closure audit
**Scope:** all nine owned tables, ephemeral coordination state, version metadata, CI, traceability, packaging and historical evidence

## Defect F24-D055 — partial schema verification

The plugin created nine canonical tables but `Schema::verify()` checked required columns in only four tables and only a subset of those columns. A damaged or incomplete events, controls, privacy, manifests or assurance table could therefore pass same-version boot and allow runtime code to execute against an absent critical column.

## Correction

- declared the complete required-column contract for every File 24-owned table;
- verified every created column in events, incidents, findings, risks, controls, privacy requests, module manifests, governance decisions and assurance records;
- made an empty/uninspectable column result a typed boot-blocking failure;
- expanded the database test double and added missing-column probes across previously unchecked tables.

## Defect F24-D056 — uninstall left option-backed locks behind

Upgrade locking had migrated to an atomic option, but uninstall still deleted only the old transient. Security-state, retention and audit-gap mutation locks were likewise absent from uninstall cleanup. Reinstalling after uninstall could therefore encounter a stale lock and fail closed indefinitely even though no worker remained.

## Correction

- removed option-backed upgrade, security-state, retention and audit-gap locks during uninstall;
- removed legacy upgrade/retention transient forms for backward compatibility;
- preserved all durable events, risks, findings, incidents, controls, privacy, manifests, governance, assurance, audit gaps, schema and version evidence;
- added functional uninstall assertions for capability removal, ephemeral cleanup and evidence preservation.

## Release and evidence correction

- promoted the corrective runtime to 0.25.8 while retaining schema 0.25.5 because no table shape changed;
- aligned plugin header, runtime constant, WordPress stable tag, self manifest, SPDX SBOM, license inventory, README, architecture, integration, migration, rollback, known limitations and requirements traceability;
- made Cycles 18–21 permanent PHP 8.0/8.3 CI gates;
- regenerated source checksums and deterministic package evidence;
- preserved all earlier Cycle 12–17 records as historical evidence rather than rewriting them.

## Review result after correction

Same-version boot now fails closed for any missing required File 24 column, not merely selected governance columns. Uninstall removes only ephemeral coordination state and delegated capabilities while retaining evidence. Source, tests, documentation, SBOM, package identity and CI now describe one 0.25.8 / schema 0.25.5 Foundation candidate.
