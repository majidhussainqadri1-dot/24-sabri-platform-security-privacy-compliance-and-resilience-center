# Security Policy

## Supported version

The project is currently in foundation development. No release should be treated as production-ready until staging acceptance, independent security review, restore testing, and Founder approval are complete.

## Reporting a vulnerability

Do not disclose exploitable details in public issues or pull requests. Use the repository owner's private GitHub security-reporting channel or another privately agreed channel.

Include:

- affected version and component;
- reproducible steps;
- impact assessment;
- proof of concept with sensitive data removed;
- suggested remediation, when known.

Never include passwords, tokens, identity documents, patient data, private messages, production database extracts, or encryption keys.

## Foundation 0.27.0 public-safe hardening

The current candidate rejects direct contact data in audit context, path-like evidence references, untrusted privacy callbacks, stale control/assurance writes, unresolved evidence eviction and inexact canonical inserts. Sensitive operations evidence remains private.
