=== Sabri Platform Security, Privacy, Compliance and Resilience Center ===
Contributors: sabrihomeopathy
Tags: security, privacy, compliance, resilience, audit
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 0.25.3
License: GPLv2 or later

Central governance and assurance control plane for the Sabri Social Homeopathy Platform.

== Description ==

Foundation 0.25.3 provides a private Security Center dashboard, bounded module manifests and audit events, risk/incident/control foundations, a private security-findings triage interface, durable and replay-resistant privacy-request orchestration, bounded retry policy and reconciliation operations, private privacy operations, advisory security-state requests, system checks, non-destructive repair, and sanitized REST status/Trust Center payloads.

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

= 0.25.3 =
* Added a dedicated privacy-policy layer while preserving the canonical repository as the storage owner.
* Enforced retry backoff and bounded attempt limits in backend processing.
* Restricted retry to explicitly retry-safe native failures; unsafe or mixed outcomes require manual reconciliation.
* Rejected completion callbacks before module claim and preserved closed-request replay protection.
* Added bounded request-detail and per-module reconciliation evidence to the private Privacy Requests dashboard.
* Added privacy-policy regression tests covering unsafe failures, callback integrity, retry timing, attempt limits and stale operations.

= 0.25.2 =
* Added durable per-module privacy result evidence and optimistic request locking.
* Added native-module completion callbacks with truthful request-level closure.
* Added bounded retries that never replay completed or pending module operations.
* Added stale-dispatch detection and hourly recovery scanning.
* Added private retry controls and exact deletion confirmation enforcement.

= 0.25.1 =
* Hardened privacy dispatch with durable pre-operation records, replay resistance, truthful pending/completed aggregation and recovery-required evidence.
* Added a private Privacy Requests dashboard with verified-subject dispatch and deletion confirmation.
* Corrected findings-page stylesheet loading and accountability-note persistence.
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
