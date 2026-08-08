<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\EndpointGuard;

function c170(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$guard = new EndpointGuard();
$GLOBALS['current_user_id'] = 0;
$policy = [
    'methods' => ['POST'],
    'require_auth' => false,
    'same_origin' => false,
    'rate_scope' => 'cycle170',
    'rate_limit' => 10,
    'rate_window' => 60,
    'require_idempotency' => true,
];

$missingIdentity = $guard->authorize($policy, ['method' => 'POST', 'idempotency_key' => 'idem:cycle170']);
c170(is_wp_error($missingIdentity) && $missingIdentity->get_error_code() === 'spcrc_endpoint_network_identity_missing', 'Anonymous protected requests must fail closed without network identity instead of sharing one global bucket.');

$invalidRate = $guard->authorize(array_replace($policy, ['rate_limit' => -10]), [
    'method' => 'POST', 'network_identifier' => '198.51.100.10', 'idempotency_key' => 'idem:invalid-rate',
]);
c170(is_wp_error($invalidRate) && $invalidRate->get_error_code() === 'spcrc_endpoint_rate_policy_invalid', 'Negative rate policy values must not be absint-coerced into a valid policy.');

$first = $guard->authorize($policy, [
    'method' => 'POST', 'network_identifier' => '198.51.100.11', 'idempotency_key' => 'idem:shared-key',
]);
$secondPrincipal = $guard->authorize($policy, [
    'method' => 'POST', 'network_identifier' => '198.51.100.12', 'idempotency_key' => 'idem:shared-key',
]);
$replay = $guard->authorize($policy, [
    'method' => 'POST', 'network_identifier' => '198.51.100.11', 'idempotency_key' => 'idem:shared-key',
]);
c170(is_array($first) && is_array($secondPrincipal), 'Identical idempotency keys from different principals must be isolated, not cross-tenant blocked.');
c170(is_wp_error($replay) && $replay->get_error_code() === 'spcrc_endpoint_replay_detected', 'A replay from the same principal must still be blocked.');

$overflowSafe = $guard->verifyWebhook('provider', '{}', str_repeat('a', 64), PHP_INT_MIN, static fn(string $provider): string => str_repeat('s', 32));
c170(is_wp_error($overflowSafe) && $overflowSafe->get_error_code() === 'spcrc_webhook_request_invalid', 'Extreme webhook timestamps must fail closed without arithmetic overflow behavior.');

$now = time();
$body = '{"ok":true}';
$secretFailure = $guard->verifyWebhook('provider', $body, str_repeat('a', 64), $now, static function (string $provider): string {
    throw new RuntimeException('vault unavailable');
});
c170(is_wp_error($secretFailure) && $secretFailure->get_error_code() === 'spcrc_webhook_secret_unavailable', 'Secret-resolver exceptions must become fail-closed webhook errors rather than escaping the guard.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Security/EndpointGuard.php');
c170(is_string($source) && str_contains($source, 'spcrc_endpoint_rate_policy_invalid') && str_contains($source, '$idempotencyScope'), 'Endpoint hardening source must remain present.');

echo "PASS: cycle170 endpoint principal isolation, strict rate policy and webhook fail-closed defects fixed and retested\n";
