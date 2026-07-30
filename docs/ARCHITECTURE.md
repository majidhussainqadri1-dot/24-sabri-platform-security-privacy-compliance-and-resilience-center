# Architecture — Foundation 0.25.0

## Core law

File 24 is a governance and assurance plane, not a replacement authentication or authorization engine.

## Ownership

- File 00 owns identity, roles, verification, MFA, and suspension.
- Native modules own their records and object-level authorization.
- File 20 owns global shell and rendered safe-mode behavior.
- File 24 owns module posture, risks/findings metadata, incident coordination metadata, privacy orchestration, control evidence, and resilience evidence.

## Fail-safe behavior

- File 24 dashboard failure must not disable native security enforcement.
- Missing File 00 identity assurance causes privileged writes to fail closed in the affected native modules.
- Missing external logging or backup evidence produces `Unknown` or `Warning`, never `Secure`.
- Optional integration failure affects only that integration panel.

## Public/private split

The public repository contains source, sanitized documentation, checksums, and public security policy. Live risks, vulnerabilities, forensic evidence, vendor contracts, backup locations, and incident playbooks belong in a private security-operations store.
