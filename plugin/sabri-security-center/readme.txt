=== Sabri Platform Security, Privacy, Compliance and Resilience Center ===
Contributors: sabrihomeopathy
Tags: security, privacy, compliance, resilience, audit
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 0.25.0
License: GPLv2 or later

Central governance and assurance control plane for the Sabri Social Homeopathy Platform.

== Description ==

Foundation 0.25.0 provides a private Security Center dashboard, module manifest registry, bounded audit events, privacy request dispatch contracts, security-state requests, system checks, and a sanitized public Trust Center REST payload.

It does not replace native module authorization, File 00 identity, hosting security, legal counsel, or independent testing.

== Installation ==

1. Install on staging only.
2. Activate the plugin.
3. Confirm administrator capabilities.
4. Connect File 00 through the `spcrc/identity_authority_available` filter.
5. Register module manifests through `spcrc/module_manifests` or `spcrc/register_module_manifest`.
6. Run Security Center system checks.

== Changelog ==

= 0.25.0 =
* Initial foundation implementation.
