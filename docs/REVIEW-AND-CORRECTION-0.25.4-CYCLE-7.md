# File 24 Review and Correction — Cycle 7

## Release identity

- Plugin candidate: `0.25.4`
- Schema revision: `0.25.3`
- Pull request status: Draft and unmerged
- Environment status: automated foundation QA only; WordPress, MySQL and Hostinger staging acceptance remain outstanding

## Governing boundary

File 24 remains a security-governance and assurance control plane. It does not become the canonical owner of File 00 identity data, native module authorization, exported personal data, clinical records, identity documents, credentials, File 20 enforcement, hosting controls or legal determinations.

## Defects found in Cycle 7

1. A valid WordPress account was being treated as sufficient proof that identity and request authority had been verified.
2. Privacy-request records lacked durable, bounded evidence of the verification method, authority basis, verifier, timestamp and opaque case reference.
3. Free-form text could be entered as a purported opaque reference, allowing personal information to be copied into orchestration metadata.
4. Email, guardian and authorized-agent verification labels could be selected without a native confirmation adapter.
5. Authenticated-session verification did not prove that the current session belonged to the privacy subject.
6. Deletion retries did not require a fresh destructive-operation confirmation.
7. Invalid module selections and undeclared privacy operations could create request records before failing.
8. A malformed or missing retry timestamp could become immediately retryable.
9. A retry assignee was not independently validated at the policy boundary.
10. Legacy records without verification evidence could become eligible for automatic retry after migration.
11. Verification methods and authority bases were not checked for semantic compatibility.
12. Future verification timestamps and invalid due dates were not rejected explicitly.
13. The File 00 adapter described exporter or eraser availability as a queued workflow even though it had not initiated the native WordPress privacy process.
14. Schema or required retention-schedule failure was recorded, but `Plugin::boot()` still continued registering operational services.
15. The superseded unverified Privacy Admin implementation remained in the source tree and could confuse future maintainers.

## Corrections applied

### Verified intake

Every new privacy dispatch now requires explicit identity-and-authority attestation plus bounded evidence:

- verification method;
- authority basis;
- opaque verification reference;
- verifying operator user ID;
- verification timestamp.

Only bounded orchestration metadata is stored. Raw identity documents, exported personal data, credentials and clinical records are prohibited from this record.

Verification references must use a namespaced opaque identifier such as `case:privacy-2026-001`. Free-form names, addresses, email addresses and narrative text are rejected.

Manual document review may be attested by an authorized operator without storing the document. Authenticated-session verification is accepted only when the current user, verifier and privacy subject are the same user. Email, guardian and authorized-agent methods fail closed unless a native module confirms the evidence through the verification adapter contract.

### Canonical storage and migration

The existing privacy-request table remains canonical. Schema `0.25.3` adds bounded verification columns and supporting indexes. A separate policy-layer store writes those columns using request status and optimistic lock-version checks.

If evidence storage fails after the initial durable request insert, the request is moved toward `recovery-required` and native module execution is not started.

Legacy rows with no valid verification evidence remain visible and may receive native completion callbacks for already-dispatched work, but they are not eligible for automatic retry.

### Module preflight

All selected modules are checked before request creation. Unknown modules and undeclared privacy operations fail before canonical storage is changed and before any native handler runs.

### Retry hardening

Automatic retry now requires all of the following:

- retryable request status;
- valid persisted verification evidence;
- attempt count below the configured maximum;
- valid and due retry timestamp;
- a valid assigned operator;
- only explicitly retry-safe module failures;
- no uncertain, pending, dispatching or completed module replay.

Deletion retries additionally require the exact fresh phrase:

`RETRY DELETION <request-uuid>`

### Fail-closed upgrade and boot

`UpgradeManager::maybeUpgrade()` now returns an explicit success or `WP_Error` contract. Schema-install failure, upgrade exception or required retention-schedule failure blocks normal File 24 runtime boot. Only a privileged generic administrator notice and a `boot_blocked` event are registered; operational services, privacy handlers and normal `booted` events are not registered.

### File 00 truthfulness

The File 00 adapter now reports exporter or eraser availability as `pending` and explicitly states that File 24 has not started the native WordPress privacy workflow. Native initiation and completion remain separate acceptance work.

### Admin ownership

`VerifiedPrivacyAdmin` is now the only active privacy administration interface. The superseded `PrivacyAdmin` source was removed.

## Automated acceptance added or extended

Cycle 7 tests cover:

- explicit verification attestation;
- verification-method and authority-basis compatibility;
- opaque-reference enforcement;
- method-specific and native verification proof;
- authenticated-session subject matching;
- future-timestamp rejection;
- durable verification evidence;
- unknown-module and undeclared-operation preflight;
- malformed retry-time rejection;
- bounded retry attempts;
- legacy-record automatic-retry denial;
- deletion retry re-authorization;
- callback-before-claim rejection;
- closed-request callback replay rejection;
- stale-operation reconciliation;
- duplicate-side-effect prevention;
- plugin and schema migration separation;
- schema and retention failure boot blocking;
- generic non-sensitive upgrade-failure notice;
- PHP syntax, secret scanning, checksums and reproducible packaging.

## Explicitly incomplete

This corrective cycle does not prove production readiness. The following remain mandatory gates:

- real WordPress fresh-install and activation testing;
- real MySQL migration and rollback testing;
- File 00 native exporter and eraser initiation plus completion callbacks;
- native email, guardian and authorized-agent verification adapters;
- File 20 staging integration;
- abuse-case and authorization testing;
- visual accessibility and responsive inspection;
- Hostinger staging acceptance;
- backup and restore evidence;
- operational procedures and Founder approval.

## Merge rule

Keep the pull request Draft and unmerged until the remaining staging and operational acceptance gates are completed and every newly discovered defect is corrected and retested.
