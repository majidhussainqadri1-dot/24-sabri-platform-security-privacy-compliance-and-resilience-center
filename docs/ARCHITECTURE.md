# Architecture — Foundation 0.25.1

## Core law

File 24 is a governance and assurance plane, not a replacement authentication or authorization engine and not a security single point of failure.

## Ownership

- File 00 owns identity, roles, verification, MFA and suspension.
- Native modules own their records and object-level authorization.
- File 20 owns global shell and rendered safe-mode behavior.
- File 24 owns module posture, risks/findings metadata, incident coordination metadata, privacy orchestration, security-state request metadata, control evidence and resilience evidence.

## Fail-safe behavior

- File 24 dashboard failure must not disable native security enforcement.
- Missing File 00 identity assurance causes privileged writes to fail closed in affected native modules; File 24 only reports the absence.
- Missing external logging or backup evidence produces `Warning` or `Unknown`, never `Secure`.
- Optional integration failure affects only that integration panel.
- Private status output is no-store and capability protected.

## Persistence boundaries

- Audit events are bounded, redacted and retained under a scheduled retention policy.
- Security-state requests persist with expiry and explicit resolution.
- Privacy requests persist metadata only; native modules retain the requested personal data and export/delete responsibilities.
- Public Trust Center output passes through a final allowlist after extension filters.

## Public/private split

The public repository contains source, sanitized documentation, checksums and public security policy. Live risks, vulnerabilities, forensic evidence, vendor contracts, backup locations, regulator contacts and internal incident playbooks belong in a private security-operations store.
