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

Optional bounded fields:

- `capabilities`
- `external_vendors`
- `posture`
- `last_security_test`
- `privacy_operations`

Unknown fields are discarded before persistence. Arrays, text lengths, manifest count and posture values are bounded. Unchanged manifests do not create a database write on every request; only a periodic heartbeat is updated.

## File 00 identity assurance

Foundation 0.25.1 detects the actual Membership Core contract when all of these exist:

- `SMC_VERSION`
- `smc_user_status()`
- `smc_is_founder()`

It then registers a sanitized File 00 manifest and reports identity-authority availability. File 24 does not grant operational security capabilities merely because a user is labeled Founder. Privileged delegation remains explicit through WordPress capabilities.

A future File 00 release may additionally override:

```php
add_filter('spcrc/identity_authority_available', '__return_true');
```

Native modules remain responsible for their own authorization and suspension checks.

## File 20 security state

File 24 records bounded, expiring advisory requests through:

```php
do_action('spcrc/request_security_state', 'file-24-security-center', 'elevated-monitoring', [
    'reason' => 'Example only',
    'expires_at' => gmdate('c', time() + HOUR_IN_SECONDS),
]);
```

It emits `spcrc/security_state_requested`. Foundation 0.25.1 detects the actual File 20 constants/classes and reports whether File 20 Safe Mode is active, but it deliberately does **not** mutate File 20 settings. A native, versioned enforcement contract must be added to File 20 before automated enforcement is claimed.

Supported advisory states:

- `elevated-monitoring`
- `restricted-writes`
- `upload-lockdown`
- `messaging-lockdown`
- `identity-lockdown`
- `publishing-read-only`
- `platform-read-only`
- `incident-containment`

## Privacy dispatch

Use the returnable filter contract:

```php
$result = apply_filters(
    'spcrc/privacy_request_dispatch',
    null,
    [
        'request_type' => 'access',
        'requester_user_id' => get_current_user_id(),
    ],
    ['file-00-membership-core']
);
```

A module must declare the requested operation in `privacy_operations` and implement:

```php
add_filter('spcrc/privacy_request/file-00-membership-core', function ($result, $type, $request) {
    return ['ok' => true, 'status' => 'completed', 'reference' => 'private-reference'];
}, 10, 3);
```

A missing handler is a failure, not an accepted result. File 24 stores only orchestration metadata; native modules retain and process their own data.

## External evidence

- `spcrc/external_log_adapter_available`
- `spcrc/external_security_event`
- `spcrc/backup_evidence`

Complete backup evidence requires both `last_success_at` and `restore_tested_at`. These contracts report assurance status only; File 24 does not claim to provide off-site logging or immutable backups itself.

## Public Trust Center availability flags

Public claims are false by default until a real intake or private disclosure channel is connected and tested:

- `spcrc/privacy_request_intake_available`
- `spcrc/responsible_disclosure_channel_available`

The final public payload is whitelisted and sanitized after filters; arbitrary private fields supplied by another plugin are discarded.

## Public-browsing compatibility

The governing platform model permits anonymous reading/search while requiring login for protected actions. File 24 checks:

```php
apply_filters('spcrc/public_browsing_compatible', true);
```

The File 00 adapter reports a warning when the currently registered Membership Core `frontend_gate` redirects anonymous public browsing. File 24 does not silently disable File 00; the native owner must supply a reviewed compatibility correction.
