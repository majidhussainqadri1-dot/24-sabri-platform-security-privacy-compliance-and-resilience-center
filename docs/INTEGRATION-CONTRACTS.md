# Foundation Integration Contracts — 0.25.1

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

Optional fields include `capabilities`, `external_vendors`, `posture`, and `last_security_test`. A second, conflicting manifest with the same module key is rejected. Posture is self-reported and is not equivalent to independent assurance.

## File 00 identity assurance

File 00 may report availability as a boolean or structured evidence:

```php
add_filter('spcrc/identity_authority_available', static function (): array {
    return [
        'available' => true,
        'version'   => '1.1.0',
        'tested_at' => '2026-07-30T00:00:00Z',
    ];
});
```

Native modules remain responsible for authorization, ownership, verification and suspension checks. File 24 no longer grants blanket capabilities to a Founder account; File 00 or an authorized administrator must assign explicit capabilities.

## Security-state request

```php
do_action('spcrc/request_security_state', 'file-17-network', 'messaging-lockdown', [
    'reason'     => 'Active abuse incident',
    'expires_at' => '+1 hour',
]);
```

Requests are persisted, expire within seven days, and are emitted through `spcrc/security_state_requested`. File 20 may translate accepted requests into shell behavior. Native modules must separately enforce their own read/write restrictions.

Resolve a request through:

```php
do_action('spcrc/resolve_security_state', $requestUuid, 'resolved');
```

## Privacy request dispatch

For a result-bearing dispatch use:

```php
$result = apply_filters('spcrc/privacy_dispatch', [], $request, ['file-03-profiles']);
```

For fire-and-report integration use:

```php
do_action('spcrc/dispatch_privacy_request', $request, ['file-03-profiles']);
```

The completion result is emitted through `spcrc/privacy_request_dispatch_completed`. A module that does not respond is recorded as `not_handled`; it is never treated as accepted. Results must contain metadata only; exported personal data remains inside the native secure workflow.

## External evidence

- `spcrc/external_log_adapter_available`
- `spcrc/backup_evidence`

Backup evidence must include `status`, `last_backup_at` and `restore_tested_at`. These report assurance status only; File 24 does not claim to provide off-site logging or immutable backups itself.

## Public Trust Center availability flags

Public claims are false by default until a real intake or private disclosure channel is connected and tested:

- `spcrc/privacy_request_intake_available`
- `spcrc/responsible_disclosure_channel_available`

The final public payload is allowlisted. Extension code cannot add arbitrary secret fields to the public response.

### Verified availability evidence

A bare boolean cannot make a public Trust Center workflow available. The adapter must provide recent structured evidence:

```php
add_filter('spcrc/privacy_request_intake_available', static function (): array {
    return [
        'available' => true,
        'tested_at' => '2026-07-30T12:00:00Z',
    ];
});
```

The same rule applies to `spcrc/responsible_disclosure_channel_available`. Evidence older than the configured maximum age, missing `tested_at`, or dated in the future is rejected. The later `spcrc/public_trust_payload` filter may supply sanitized URLs and policy metadata, but it cannot elevate the verified availability booleans or replace the canonical program status.

### Backup evidence freshness

The default maximum acceptable backup age is seven days and the default maximum restore-test age is 180 days. Deployments may narrow or widen these bounded periods through `spcrc/max_backup_age_seconds` and `spcrc/max_restore_test_age_seconds`, but stale or future-dated evidence cannot pass.
