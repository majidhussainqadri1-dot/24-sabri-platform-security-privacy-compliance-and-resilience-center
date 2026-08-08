<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c188(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$modules = new ModuleRegistry();
$rp = new ReflectionProperty(ModuleRegistry::class, 'manifests');
$rp->setAccessible(true);
$rp->setValue($modules, ['cycle188' => ['module_key' => 'cycle188']]);

$GLOBALS['current_user_id'] = 0;
$GLOBALS['current_user_caps'] = [];
add_filter('spcrc/authorize_security_state_request', static fn (): bool => true, 10, 4);
add_filter('spcrc/resolve_service_actor', static fn (): bool => true, 10, 6);
$registry = new SecurityStateRegistry($modules, new AuditLogger());
c188($registry->request('cycle188', 'restricted-writes', ['reason' => 'Negative actor coercion', 'actor_user_id' => -42]) === false, 'Negative service actor must not be absint-coerced into user 42.');

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps']['spcrc_manage_security_settings'] = true;
add_filter('spcrc/security_state_default_ttl', static fn (): string => '7200seconds', 99, 3);
c188($registry->request('cycle188', 'upload-lockdown', ['reason' => 'Malformed TTL filter']) === false, 'Malformed security-state TTL must fail closed instead of coercing to a valid duration.');

$GLOBALS['wp_filters']['spcrc/security_state_default_ttl'] = [];
$futureId = '11111111-1111-4111-8111-111111111188';
$GLOBALS['wp_options']['spcrc_security_state_requests'] = [
    $futureId => [
        'request_id' => $futureId,
        'module_key' => 'cycle188',
        'state' => 'restricted-writes',
        'reason' => 'Tampered future request',
        'requested_by' => 7,
        'requested_at' => gmdate('c', time() + 3600),
        'expires_at' => gmdate('c', time() + 7200),
        'status' => 'open',
    ],
];
$reloaded = new SecurityStateRegistry($modules, new AuditLogger());
c188($reloaded->all() === [], 'Persisted security-state request with future requested_at must be rejected during reload.');
$marker = get_option('spcrc_security_state_tamper_marker', []);
c188(is_array($marker) && ($marker['rejected_records'] ?? 0) >= 1, 'Rejected persisted security-state chronology must leave durable tamper evidence.');

$externalId = '22222222-2222-4222-8222-222222222188';
$merged = $reloaded->merge([
    $externalId => [
        'request_id' => $externalId,
        'module_key' => 'cycle188',
        'state' => 'restricted-writes',
        'reason' => 'External negative actor',
        'requested_by' => -7,
        'requested_at' => gmdate('c'),
        'expires_at' => gmdate('c', time() + 1800),
    ],
]);
c188(! isset($merged[$externalId]), 'External security-state projections with negative requested_by must be rejected rather than re-attributed.');

echo "PASS: cycle188 security-state actor, TTL and persisted chronology integrity defects fixed and retested\n";
