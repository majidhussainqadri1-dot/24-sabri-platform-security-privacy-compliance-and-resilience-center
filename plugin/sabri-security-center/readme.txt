=== Sabri Platform Security, Privacy, Compliance and Resilience Center ===
Contributors: sabrihomeopathy
Tags: security, privacy, compliance, resilience, audit
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 0.26.0
License: GPLv2 or later

Central governance and assurance control plane for the Sabri Social Homeopathy Platform.

== Description ==

Foundation 0.26.0 provides a private Security Center dashboard, bounded module manifests and audit events, risk/incident/control foundations, a private security-findings triage interface, durable and replay-resistant privacy-request orchestration, bounded retry policy and reconciliation operations, verified privacy intake, fail-closed upgrade integrity, advisory security-state requests, system checks, non-destructive repair, and sanitized REST status/Trust Center payloads.

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

= 0.26.0 =
* Added twelve fresh review/correction cycles (30–41) closing expired lease resurrection, lock-token failure, audit evidence loss, audit-gap capacity, timestamp ambiguity and governance expiry races.
* Bound governance, risk and finding mutations to atomic expiry/version predicates and exact rollback identities.
* Centralized assurance rollback gaps and required exact one-row rollback evidence.
* Enforced authenticated privacy-verifier identity and capability before manual verification evidence is accepted.
* Added 91 defect-specific assertions plus final twelve-round release-closure checks, PHP 8.0/8.3 CI, checksums, SBOM and deterministic package evidence.

= 0.25.9 =
* Corrected zero-row manifest heartbeats so concurrent canonical hash drift cannot be admitted into runtime memory.
* Added exact-value atomic option locks for governance request admission, upgrades, retention, audit-gap mutations, security-state mutations and control upserts.
* Added lease renewal, owner-only release, stale-lock reclamation and malformed-lock fail-closed behavior across coordination paths.
* Hid security-state requests with unresolved audit evidence from enforcement consumers.
* Corrected privacy verification compensation so failed recovery-state persistence creates a dedicated release-blocking audit gap.
* Added eight complete review/correction cycles (22–29), 113 dedicated assertions, PHP 8.0/8.3 CI, updated checksums, SBOM and reproducible package evidence.

= 0.25.8 =
* Replaced the retention check-then-set transient with an atomic owner-token option lock, stale-lock recovery and contention failure controls.
* Enforced privacy retry safety at the canonical storage boundary so uncertain destructive outcomes cannot be replayed by bypassing dispatcher policy.
* Serialized audit-gap record and reconciliation mutations with an atomic expiring owner lock to prevent lost release blockers.
* Expanded schema verification to every required column in all nine owned tables.
* Corrected uninstall cleanup for option-backed upgrade, security-state, retention and audit-gap coordination locks while preserving durable evidence.
* Added four complete review/correction cycles (18–21), permanent regression suites, PHP 8.0/8.3 CI execution, updated checksums, SBOM and deterministic package evidence.

= 0.25.7 =
* Added a bounded governance-decision registry with independent requester/approver identities, File 00 step-up, expiry, optimistic concurrency and exact subject binding.
* Added independently keyed governance audit gaps and a separation-, capability- and step-up-protected reconciliation workflow.
* Bound critical risk and finding risk acceptance to current approved governance decisions and automatic expiry reopening.
* Added audit-atomic incident, control, risk and finding mutations; failed audit writes roll back canonical changes or emit a targeted reconciliation marker.
* Hardened Security State requests with explicit authorization, sensitive-reason rejection, duplicate suppression, 24-hour expiry, mutation locking and audit rollback.
* Added schema 0.25.5 with nine owned tables, governed-column verification, migration locking and unsafe-downgrade prevention.
* Added a bounded private Assurance Registry for compliance applicability, vendor review and backup/restore evidence metadata.
* Expanded module manifests with contract version, canonical owners, opaque evidence source, degraded behavior and release gate.
* Rejected credentials, contact data, identity-number patterns, URLs and storage paths from bounded evidence and accountability metadata.
* Required retention and privacy-recovery schedules during activation, upgrade and repair; failed activation removes partial schedules.
* Added complete uninstall capability cleanup while preserving evidence tables by default.
* Added bounded independently keyed audit-gap storage across canonical, privacy, retention, recovery, repair and automated-expiry paths; missing audit evidence now blocks release and cannot be reported as successful; generic gaps have a step-up- and evidence-gated private reconciliation path.
* Added Cycle 12–16 fresh/adversarial reviews, corrected PHP 8.0 syntax compatibility, strict authorization-filter booleans, audit-atomic assurance writes, minimized backup evidence, audit-gap System Checks, PHP 8.0/8.3 CI, secret scanning, SPDX/license evidence, checksums and deterministic package parity.

= 0.25.4 =
* Added explicit identity-and-authority verification evidence before privacy dispatch.
* Added bounded verification method, authority basis, operator, timestamp and opaque reference storage.
* Rejected free-form personal text in verification references and required namespaced opaque case identifiers.
* Required authenticated-session evidence to belong to the current privacy subject.
* Required native confirmation adapters for email, guardian and authorized-agent verification methods.
* Added pre-dispatch module-operation validation so invalid selections cannot create false native failures.
* Added fresh destructive confirmation for every deletion retry.
* Hardened retry decisions against malformed schedules, invalid assignees and legacy records without verification evidence.
* Blocked all normal File 24 runtime services when schema or required retention integrity checks fail.
* Corrected File 00 adapter wording and state so exporter/eraser availability is not falsely described as a queued native workflow.
* Removed the superseded unverified privacy administration implementation.

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
