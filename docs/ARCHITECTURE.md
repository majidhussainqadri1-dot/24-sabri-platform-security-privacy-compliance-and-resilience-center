# Architecture — Foundation 0.27.0

## Core law

File 24 is a central governance and assurance plane, not a replacement authentication, authorization, legal, backup or infrastructure engine.

## Ownership

- File 00 owns identity, roles, verification, MFA, suspension, consent and guardian context.
- Native modules own their records and object-level authorization.
- File 20 owns global shell and rendered safe-mode behavior.
- File 24 owns module posture, bounded governance decisions, risk/finding metadata, incident-coordination metadata, privacy orchestration, control evidence and assurance metadata.

## No security single point of failure

File 24 failure must not disable native authentication, authorization, private-file protection, moderation or clinical boundaries. Conversely, File 24 fails closed when its required schema, governed columns, schedules or sensitive-operation assertions cannot be verified.

## Separation of duties

The Founder identity is not automatically converted into operational security-administrator access. Capabilities are explicit, reviewable and reversible. Governance request, governance approval/reconciliation and critical-risk acceptance are distinct authorities. Requester and approver differ; an original requester cannot reconcile the resulting audit gap.

## Governance Registry

The governance registry records only bounded decision metadata, rationale hashes, opaque evidence references, subject binding, requester/approver identities, expiry and optimistic lock version. Critical-risk and finding-risk acceptance are valid only while the exact approved decision remains current. Expired acceptance is automatically reopened.

Audit failures create independently keyed governance gaps rather than a single global flag. Reconciliation requires a different authorized operator, fresh File 00 step-up and a successful reconciliation audit; unrelated gaps remain intact.

## Audit-atomic domain repositories

Risks, findings, incidents and controls are canonical only when their corresponding audit event is durable. On audit-write failure:

- a new record is deleted;
- an update restores the exact prior canonical fields;
- a targeted audit-gap marker is created only if rollback itself cannot be proved.

Free-form accountability text is not copied into ordinary audit context; hashes and bounded references are used instead.

## Persistence and migration integrity

- Schema 0.25.5 owns nine tables, including `spcrc_governance_decisions`.
- Installation, same-version boot, upgrade, repair and System Check verify tables and governed columns.
- Upgrade uses an atomic option lock, rejects lock contention, detects stale locks and releases the lock in `finally`.
- Unsafe downgrade is blocked when installed plugin/schema versions exceed the running package.
- Plugin/schema version options advance only after schema, capabilities, retention and privacy-recovery schedules pass.
- Failed activation removes partially created File 24 schedules.
- Module keys are bound to persisted name/owner identity and cannot be destructively rebound.
- Manifest changes use guarded insert/update semantics; destructive `REPLACE` is prohibited.

## Security-state requests

Security-state requests are advisory, capability/contract-authorized, non-sensitive, duplicate-suppressed and limited to a maximum 24-hour lifetime. Request and resolution mutations are lock-protected and audit-atomic. File 20 remains the enforcement owner.

## Privacy orchestration

Malformed or unsupported verification evidence is rejected before a canonical privacy-request row is created. Native side effects are never automatically replayed when completion is uncertain. Pending/completed work remains protected from unsafe retry.

## Assurance Registry

The registry supports three bounded record types:

- compliance applicability;
- vendor/subprocessor review;
- backup and restore evidence.

It stores status, owner, jurisdiction, data classes, review timestamps and opaque evidence references. It rejects secret-like material, personal contact data, identity-number patterns, URLs and storage paths. Final compliance/vendor determinations require completed review evidence. A verified backup requires successful backup evidence, a later restore test and an opaque reference.

The registry exposes a minimized read-only `spcrc/backup_evidence` adapter. It has no generic write-through hook; mutations require a capability- and nonce-protected private workflow or an explicit trusted repository call.

## Public/private split

The public repository contains source, sanitized documentation, checksums and public security policy. Live risks, vulnerabilities, forensic evidence, vendor contracts, backup locations and incident playbooks belong in a private security-operations store.

## Runtime compatibility

The package declares PHP 8.0 minimum support. Production and test code therefore avoid PHP 8.1-only `never` return types and `array_is_list()`, and PHP 8.2-only standalone `true` union types. GitHub CI validates PHP 8.0 and 8.3 independently.


## Audit-evidence gap plane

`Storage/AuditGapStore` is a bounded fail-closed release-blocker registry. It is used only when required canonical audit evidence cannot be durably stored; it never substitutes for the append-only security-event table. Privacy, retention, recovery, repair, canonical rollback and automated-expiry paths emit independently keyed sanitized gaps. `SystemCheck` aggregates category counts without exposing sensitive content. Generic operational gaps have a private reconciliation surface requiring capability, nonce, fresh File 00 step-up, opaque private evidence and a successful authorization audit; native governance/security-state/assurance workflows remain separate.

## Four-round concurrency and integrity closure (0.25.8)

- Retention cleanup owns `spcrc_retention_lock` through atomic option creation, an expiring owner token and owner-matched release.
- Audit-gap record and reconciliation mutations share `spcrc_audit_gap_store_lock`; active contention fails closed and expired orphan locks are reclaimed.
- Privacy retry safety is enforced in both the policy and canonical repository. Only never-started or explicitly `retry-safe-` module outcomes may replay.
- Same-version boot verifies every required column in all nine owned tables before File 24 runtime services are considered healthy.
- Uninstall removes delegated capabilities and ephemeral coordination state only; durable security, privacy, governance, assurance and audit-gap evidence remains preserved.

## Eight-round concurrency and compensation closure (0.25.9)

Cycles 22–29 standardize exact-value option locks, lease renewal and owner-only release across governance admission, upgrade, retention, audit-gap, security-state and control mutations. Manifest heartbeat admission now proves canonical identity after a zero-row write. Privacy verification compensation is checked and creates bounded release-blocking evidence when recovery state cannot be persisted.


## Twelve-round atomicity and evidence closure (0.26.0)

Cycles 30–41 add fail-closed expired-lease handling, cryptographically validated lock-token generation, exact audit-write evidence, non-evicting bounded gap capacity, strict absolute timestamps, governance lease and expiry binding, optimistic concurrency for risk/finding state, centrally managed assurance rollback gaps and authenticated privacy-verifier authority. These controls preserve native ownership and do not claim external staging or operational acceptance.

## Fifteen-round integrity closure (0.27.0)

Foundation 0.27.0 adds non-evicting state/gap capacity, validated secure identifiers, contact-data pseudonymization, same-origin manifest routes, governance fallback gaps, exact create semantics, retention evidence proof, optimistic control/assurance concurrency and module-bound privacy callbacks with fresh deletion-retry step-up.
