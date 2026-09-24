# File 24 Integration Contracts — 0.99.0

## Contract law

File 24 is the governance and assurance plane. Every integration is versioned, bounded, fail-closed for File 24-owned sensitive actions, and non-authoritative for another module's canonical data. Feature detection never substitutes for authorization.

## Module manifest

Modules may return manifests through `spcrc/module_manifests` or call `spcrc/register_module_manifest`.

Identity fields are required: `module_key`, `name`, `version`, `owner`, `data_classes`, `public_routes`, `private_routes`.

A **complete current assurance contract** additionally requires: `tables`, `files`, `capabilities`, `external_vendors`, `secret_classes`, `privacy_operations`, `exporters`, `erasers`, `emergency_callbacks`, `last_security_test`, `verification_level`, `contract_version`, `canonical_data_owner`, `canonical_action_owner`, `evidence_source`, `degraded_behavior` and `release_gate`.

`last_security_test` may not be blank for a complete manifest and must be a valid non-future timestamp. `contract_version` must be inside the explicit File 24 supported range. Versions below the minimum are `deprecated`; an unreviewed next major version is `blocked`. A parseable but incomplete/deprecated manifest remains registered only as `unassessed` and must not be presented as operational.

A persisted `module_key` is permanently bound to its sanitized module name and owner unless an approved migration transfers ownership. Unknown fields are discarded. Persistence uses guarded insert/update and concurrent-write detection; destructive replacement is prohibited.

`ContractCompatibilityPolicy` is the executable deprecation/compatibility authority for the File 24 manifest contract. File 00, File 02 and File 20 adapters also publish explicit `spcrc/file00_contract_state`, `spcrc/file02_contract_state` and `spcrc/file20_contract_state` results from the native contract surfaces they actually detect.

## File 00 identity and step-up authority

File 24 consumes File 00 identity, suspension, capability and step-up assertions but does not create a parallel identity system. Native modules remain responsible for object authorization and privacy-subject checks.

Sensitive governance decisions call the versioned filter:

```php
$verified = apply_filters(
    'spcrc/verify_step_up_assurance',
    false,
    $operatorUserId,
    'governance:' . $decisionType,
    $opaqueStepUpReference
);
```

The result must be an explicit current `true`. Missing File 00 support, stale assurance, an empty/non-opaque reference or a mismatched purpose fails closed.

## Governance decision contract

File 24 owns bounded governance decision metadata for critical-risk acceptance, finding-risk acceptance, policy exceptions, production restore, key rotation, incident closure and mass restriction.

- Request requires `spcrc_request_governance_decision`.
- Approval/rejection/revocation and audit-gap reconciliation require `spcrc_approve_governance_decision`.
- Critical-risk/finding acceptance additionally requires `spcrc_accept_critical_risk`.
- Requester and approver must differ.
- A reconciler cannot be the original requester.
- Decisions are bound to one exact decision type and subject key, expire, use optimistic locking and store only hashes plus opaque evidence references.
- A failed decision/reconciliation audit preserves a targeted audit-gap marker; the exact gap is cleared only after independent, step-up-protected reconciliation and successful reconciliation audit.

Neither approval nor critical-risk acceptance capability is auto-granted.

## File 20 security-state contract

`spcrc/request_security_state` records bounded, expiring advisory requests. File 20 remains the native owner of rendered Safe Mode, maintenance/read-only behavior and shell restrictions.

A request is accepted only when the actor has `spcrc_manage_security_settings` or an explicit versioned authorization bridge returns true through `spcrc/authorize_security_state_request`. Resolution uses a separate `spcrc/authorize_security_state_resolution` bridge when the native capability is absent.

Requests require a non-sensitive reason, expire within 24 hours, suppress duplicate open module/state requests, use a mutation lock and roll back if audit evidence cannot be stored. File 24 never silently mutates File 20 settings.

## Privacy dispatch

```php
$result = apply_filters(
    'spcrc/privacy_request_dispatch',
    null,
    $verifiedRequest,
    ['file-00-membership-core']
);
```

Before canonical request creation, File 24 validates the subject, assignee, due-date syntax, method/authority pair, non-future verifier timestamp, opaque evidence reference and method-specific proof. Invalid evidence creates no privacy row.

A module must declare the requested operation and implement `spcrc/privacy_request/{module-key}`. Pending or uncertain native work is not automatically replayed.

## Native completion and bounded retry

`spcrc/privacy_request_module_result` records bounded native completion callbacks. Completed and pending module operations are never replayed. Failed work is retryable only when the native result explicitly declares retry safety with the canonical `retry-safe-` code prefix; deletion retry also requires fresh destructive confirmation. This invariant is enforced again by `PrivacyRequestRepository::claimRetry()` so internal callers cannot bypass dispatcher policy.

## Stale-dispatch recovery

`spcrc_privacy_recovery_scan` runs hourly. It marks stale dispatching requests `recovery-required`; this does not authorize automatic replay.

## Assurance write boundary

Normal operator writes use the private admin action `admin_post_spcrc_upsert_assurance`, protected by `spcrc_manage_assurance` and a WordPress nonce. There is deliberately no generic public/filter write contract.

Trusted internal code may instantiate `AssuranceRepository` and call `upsert()` with bounded metadata. Final compliance/vendor determinations require a completed review timestamp and opaque evidence reference.

## Backup evidence adapter

`spcrc/backup_evidence` returns only:

- `status`;
- `last_success_at`;
- `restore_tested_at`;
- bounded `evidence_ref`.

Unknown upstream fields are discarded. `verified` backup posture requires successful-backup evidence, a later restore test and an opaque private reference. File 24 reports evidence status only; it is not the backup engine or storage provider.

## External evidence and Trust Center

- `spcrc/external_log_adapter_available`
- `spcrc/external_security_event`
- `spcrc/privacy_request_intake_available`
- `spcrc/responsible_disclosure_channel_available`

Public Trust Center output is allowlisted after filters. Arbitrary private fields are discarded, and the public program status remains `Foundation candidate; production assurance pending` until independent release gates are evidenced.

## Current 0.99.0 contract additions

Privacy module callbacks default to deny and require an opaque native authority reference through `spcrc/authorize_privacy_module_callback`. Deletion retries require File 00 step-up through `spcrc/verify_step_up_assurance` with purpose `privacy:deletion-retry`. Manifest routes are same-origin path-only contracts.


## Measurable performance and launch blockers

F24-R092 is enforced by `PerformanceObjectiveContract`: all eight governed metrics (ingestion, burst, dashboard p95, backlog, retry recovery, data-loss tolerance, export time and storage growth) require a metric-specific unit/direction, finite threshold, environment, effective version and measurement window. Actual thresholds and measurements remain staging/operational evidence.

F24-R096 uses the governed `launch-blocker` artifact domain plus `LaunchBlockerContract`. Every critical blocker requires an accountable owner, due date, affected feature and fail-closed feature state while unresolved; closure requires opaque verification evidence, and accepted risk requires a governed decision reference.
