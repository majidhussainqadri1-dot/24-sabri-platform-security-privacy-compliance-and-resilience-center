# Foundation Integration Contracts

## Module manifest

Modules can return manifests through the `spcrc/module_manifests` filter or call the `spcrc/register_module_manifest` action.

Required fields:

- `module_key`
- `name`
- `version`
- `owner`
- `data_classes`
- `public_routes`
- `private_routes`

Optional fields include `capabilities`, `external_vendors`, `posture`, and `last_security_test`.

## File 00 identity assurance

File 00 should return `true` from:

```php
add_filter('spcrc/identity_authority_available', '__return_true');
```

Native modules remain responsible for their own authorization and suspension checks.

## File 20 security state

File 24 emits `spcrc/security_state_requested`. File 20 may translate accepted requests into global shell behavior. Native modules must separately enforce their own read/write restrictions.

## External evidence

- `spcrc/external_log_adapter_available`
- `spcrc/backup_evidence`

These report assurance status only; File 24 does not claim to provide off-site logging or immutable backups itself.

## Public Trust Center availability flags

Public claims are false by default until a real intake or private disclosure channel is connected:

- `spcrc/privacy_request_intake_available`
- `spcrc/responsible_disclosure_channel_available`

A module or platform adapter must return `true` only after the underlying workflow is operational and tested.
