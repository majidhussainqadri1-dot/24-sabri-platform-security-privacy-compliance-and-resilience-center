# Foundation Integration Contracts — 0.25.6

## Module manifest

Modules may return manifests through `spcrc/module_manifests` or call `spcrc/register_module_manifest`.

Required fields: `module_key`, `name`, `version`, `owner`, `data_classes`, `public_routes`, `private_routes`.

Optional bounded fields: `capabilities`, `external_vendors`, `posture`, `last_security_test`, `privacy_operations`.

A persisted `module_key` is permanently bound to its sanitized module name and owner unless a future approved migration explicitly transfers ownership. Unknown fields are discarded. Manifest persistence uses guarded insert/update and detects concurrent changes; it never uses destructive replacement.

## File 00 identity authority

File 24 consumes File 00 identity and authorization claims but does not create a parallel identity system. Native modules remain responsible for object authorization, suspension and privacy-subject checks.

## File 20 security state

`spcrc/request_security_state` records bounded, expiring advisory requests. File 20 remains the native owner of rendered Safe Mode and shell restrictions. File 24 does not silently mutate File 20 settings.

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

`spcrc/privacy_request_module_result` records bounded native completion callbacks. Completed and pending module operations are never replayed. Failed work is retryable only when the native result explicitly declares retry safety; deletion retry also requires fresh destructive confirmation.

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

Unknown upstream fields are discarded. File 24 reports evidence status only; it is not the backup engine or storage provider.

## External evidence and Trust Center

- `spcrc/external_log_adapter_available`
- `spcrc/external_security_event`
- `spcrc/privacy_request_intake_available`
- `spcrc/responsible_disclosure_channel_available`

Public Trust Center output is whitelisted after filters. Arbitrary private fields are discarded.
