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

Foundation 0.25.1 provides a private Security Center dashboard, bounded module manifests and audit events, risk/incident/control foundations, a private security-findings triage interface, privacy-request orchestration, advisory security-state requests, system checks, non-destructive repair, and sanitized REST status/Trust Center payloads.

It does not replace native-module authorization, File 00 identity, File 20 enforcement, hosting security, legal counsel, backups, or independent security testing.

== Installation ==

1. Install on staging only.
2. Activate the plugin and verify the schema/capability checks.
3. Confirm the correct operational roles have explicit File 24 capabilities.
4. Grant `spcrc_accept_critical_risk` only through an explicit, reviewable delegation; it is deliberately not auto-granted.
5. Confirm File 00 and File 20 are detected without bypassing their native ownership.
6. Register companion-module manifests.
7. Connect real external logging and backup/restore evidence adapters.
8. Run Security Center checks and the non-destructive repair only when needed.

== Changelog ==

= 0.25.1 =
* Removed automatic Founder security-administrator escalation.
* Added bounded manifest, audit and state persistence with truthful failure handling.
* Added real File 00/File 20 adapters and public-browsing compatibility detection.
* Added risk, incident and control-catalog foundation workflows.
* Added verified non-destructive repair, stronger REST minimization and expanded QA/build tooling.
* Added a private findings triage interface with controlled transitions, optimistic concurrency and accountable status changes.
* Added an explicitly delegated risk-acceptance capability that is not granted automatically.
* Added runtime contract tests to detect missing boot-time method integrations.

= 0.25.0 =
* Initial foundation implementation.
