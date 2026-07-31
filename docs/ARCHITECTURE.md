# Architecture — Foundation 0.25.6

## Core law

File 24 is a central governance and assurance plane, not a replacement authentication, authorization, legal, backup or infrastructure engine.

## Ownership

- File 00 owns identity, roles, verification, MFA, suspension, consent and guardian context.
- Native modules own their records and object-level authorization.
- File 20 owns global shell and rendered safe-mode behavior.
- File 24 owns module posture, risk/finding metadata, incident-coordination metadata, privacy orchestration, control evidence and bounded assurance metadata.

## No security single point of failure

File 24 failure must not disable native authentication, authorization, private-file protection, moderation or clinical boundaries. Conversely, File 24 itself fails closed when its own required schema or runtime schedules cannot be verified.

## Separation of duties

The Founder identity is not automatically converted into operational security-administrator access. Capabilities are explicit, reviewable and reversible. Critical-risk acceptance remains a separately delegated capability.

## Persistence integrity

- Schema installation and same-version runtime boot verify all File 24-owned tables.
- Plugin/schema version options are verified after activation, upgrade and repair.
- Retention and privacy-recovery schedules are required integrity dependencies.
- Failed activation removes partially created File 24 schedules.
- Module keys are bound to persisted name/owner identity and cannot be destructively rebound.
- Manifest changes use guarded insert/update semantics; destructive `REPLACE` is prohibited.

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
