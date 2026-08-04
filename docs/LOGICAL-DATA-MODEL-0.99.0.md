# File 24 0.99.0 — Logical Data Model

## Canonical relational tables

The schema intentionally keeps nine canonical, query-intensive domains in dedicated tables: security events, incidents, findings, risks, controls, privacy requests, module manifests, governance decisions and assurance records.

## Bounded governed artifact registry

Lower-volume governance metadata uses a bounded, lock-protected, audit-bound logical registry with 28 domain types: policies, exceptions, assets, data inventory, processing activities, consent, legal holds, vulnerabilities, external dependencies, secret/key metadata, continuity/BIA/recovery/drills, trust claims, performance objectives, release gates, training, integrations, security tests, deletion ledger, alerts, remote evidence, jobs, incident actions, upload assurance and private delivery.

## Ownership constraints

Raw patient charts, message bodies, identity documents, payment credentials, provider secrets, private runbooks, forensic payloads and backup locations are not File 24 records. The registry stores bounded metadata and opaque evidence references only. Indexes/caches/projections are rebuildable and never grant authorization.
