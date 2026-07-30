# Architecture — Foundation 0.25.1

## Core law

File 24 is a governance and assurance plane, not a replacement authentication or authorization engine.

## Ownership

- File 00 owns identity, roles, verification, MFA and suspension.
- Native modules own their records and object-level authorization.
- File 20 owns global shell and rendered safe-mode behavior.
- File 24 owns module posture, risks/findings metadata, incident-coordination metadata, privacy orchestration, control evidence and resilience evidence.

## Separation of duties

The Founder identity is not automatically converted into operational security-administrator access. Security capabilities are explicitly assigned through roles/capabilities and remain reviewable and reversible.

## Fail-safe behavior

- File 24 dashboard failure must not disable native security enforcement.
- Missing File 00 identity assurance causes privileged writes to fail closed in the affected native modules.
- Missing external logging or backup evidence produces `Warning` or `Unknown`, never `Secure`.
- Optional integration failure affects only that integration panel.
- File 24 security-state requests are advisory until the native owner implements a versioned enforcement contract.

## Data minimization

- Manifest fields are whitelisted, bounded and sanitized.
- Audit contexts are recursively bounded and redact credential, identity-document, payment and clinical-message keys.
- Raw IP addresses and user agents are pseudonymized before File 24 persistence.
- Public REST output is sanitized after filters and never returns routes, capabilities, vendors, reasons or private evidence.

## Persistence

- Schema installation is verified before activation or upgrade is declared successful.
- Unchanged manifests avoid per-request database replacement; a periodic heartbeat records availability.
- Advisory security-state requests are bounded, persisted with expiry and automatically pruned.
- Privacy orchestration records status metadata but not exported personal data.

## Public/private split

The public repository contains source, sanitized documentation, checksums and public security policy. Live risks, vulnerabilities, forensic evidence, vendor contracts, backup locations and incident playbooks belong in a private security-operations store.

## Operational foundation added in 0.25.1

- The risk register stores bounded likelihood/impact metadata and no raw vulnerability proof.
- The incident register stores sanitized coordination metadata and no forensic payloads.
- The control catalog stores framework/status/evidence references, not private evidence contents.
- Non-destructive repair recreates only File 24-owned schema and capabilities.
- Operational writes require explicit capability plus nonce and are audited.
