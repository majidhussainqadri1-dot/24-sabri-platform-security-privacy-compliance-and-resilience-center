=== Sabri Platform Security, Privacy, Compliance and Resilience Center ===
Contributors: sabrihomeopathy
Tags: security, privacy, compliance, resilience, audit
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 0.25.1
License: GPLv2 or later

Central governance and assurance control plane for the Sabri Social Homeopathy Platform.

== Description ==

Foundation 0.25.1 provides a private Security Center dashboard, validated module manifest registry, bounded and redacted audit events, persisted security-state requests, privacy request dispatch contracts, system checks, retention scheduling, and a sanitized public Trust Center REST payload.

It does not replace native module authorization, File 00 identity, File 20 shell enforcement, hosting security, legal counsel, off-site evidence storage, or independent testing.

== Installation ==

1. Install on staging only.
2. Activate the plugin on one site; network-wide activation is not supported in this foundation release.
3. Confirm administrator capabilities.
4. Connect File 00 through the `spcrc/identity_authority_available` filter.
5. Register module manifests through `spcrc/module_manifests` or `spcrc/register_module_manifest`.
6. Connect structured backup and restore evidence.
7. Run Security Center system checks.

== Changelog ==

= 0.25.1 =
* Removed the blanket Founder capability bypass; privileged access now requires explicit role/capability assignment.
* Persisted security-state requests with expiry, resolution and audit evidence.
* Corrected privacy dispatch so absent handlers fail instead of appearing accepted.
* Added idempotent privacy request metadata persistence, bounded metadata-only fan-out and a result-bearing filter contract.
* Added bounded audit context, stronger redaction, schema-length enforcement, insert-failure detection and environment metadata.
* Added retention scheduling and bounded event pruning.
* Added schema verification, upgrade locking, downgrade protection and capability repair.
* Enforced a final allowlist and immutable evidence-gated availability on the public Trust Center payload.
* Added no-store headers for private REST status, freshness-aware evidence checks, manifest identity protection and improved system checks.
* Added regression tests and expanded CI across PHP 8.0 and 8.3.

= 0.25.0 =
* Initial foundation implementation.
