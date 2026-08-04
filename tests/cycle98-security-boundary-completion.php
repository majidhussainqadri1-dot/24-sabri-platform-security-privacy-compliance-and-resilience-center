<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Security\EndpointGuard;
use Sabri\Platform\Security\Security\IdentityAssurance;
use Sabri\Platform\Security\Security\NetworkPolicy;
use Sabri\Platform\Security\Security\PrivateDeliveryPolicy;
use Sabri\Platform\Security\Security\UploadPolicy;

$count = 0;
function c98(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

c98(NetworkPolicy::sameOriginUrl('https://example.test/security-center'), 'Valid same-origin HTTPS URL must pass.');
c98(! NetworkPolicy::sameOriginUrl('https://evil.example/security-center'), 'Cross-origin URL must fail.');
c98(! NetworkPolicy::safeExternalEndpoint('https://127.0.0.1/callback'), 'Loopback SSRF endpoint must fail.');
add_filter('spcrc/resolve_endpoint_ips', static fn (array $ips, string $host): array => $host === 'provider.example' ? ['8.8.8.8'] : $ips, 10, 2);
c98(NetworkPolicy::safeExternalEndpoint('https://provider.example/callback', ['provider.example']), 'Allowlisted public provider endpoint must pass.');
c98(! NetworkPolicy::safeExternalEndpoint('https://unresolved.invalid/callback', ['unresolved.invalid']), 'Unresolved external hostname must fail closed.');

$GLOBALS['current_user_caps']['spcrc_manage_controls'] = true;
$guard = new EndpointGuard();
$policy = [
    'methods' => ['POST'], 'require_auth' => true, 'capability' => 'spcrc_manage_controls',
    'nonce_action' => 'spcrc-save', 'same_origin' => true, 'rate_scope' => 'control-save',
    'rate_limit' => 2, 'rate_window' => 60, 'require_idempotency' => true,
    'object_authorizer' => static fn (array $request): bool => ($request['object'] ?? '') === 'control-01',
];
$request = [
    'method' => 'POST', 'nonce' => 'spcrc-save', 'origin' => 'https://example.test/wp-admin/',
    'idempotency_key' => 'request:control-save-01', 'object' => 'control-01',
];
$authorized = $guard->authorize($policy, $request);
c98(is_array($authorized) && ! empty($authorized['authorized']), 'Authorized endpoint request must pass all controls.');
$replay = $guard->authorize($policy, $request);
c98(is_wp_error($replay) && $replay->get_error_code() === 'spcrc_endpoint_replay_detected', 'Duplicate state-changing request must be blocked.');
$badOrigin = $request; $badOrigin['idempotency_key'] = 'request:control-save-02'; $badOrigin['origin'] = 'https://evil.example/';
$originResult = $guard->authorize($policy, $badOrigin);
c98(is_wp_error($originResult) && $originResult->get_error_code() === 'spcrc_endpoint_origin_invalid', 'Cross-origin protected request must fail.');

$secret = str_repeat('s', 40); $body = '{"event":"test"}'; $timestamp = time();
$signature = hash_hmac('sha256', $timestamp . '.' . $body, $secret);
$webhook = $guard->verifyWebhook('provider-one', $body, $signature, $timestamp, static fn (): string => $secret);
c98(is_array($webhook) && ! empty($webhook['verified']), 'HMAC webhook must verify.');
$webhookReplay = $guard->verifyWebhook('provider-one', $body, $signature, $timestamp, static fn (): string => $secret);
c98(is_wp_error($webhookReplay) && $webhookReplay->get_error_code() === 'spcrc_webhook_replay_detected', 'Webhook replay must be blocked.');

$uploads = new UploadPolicy();
$goodUpload = $uploads->validate([
    'name' => 'case-image.jpg', 'size' => 1024, 'declared_mime' => 'image/jpeg',
    'detected_mime' => 'image/jpeg', 'sha256' => str_repeat('a', 64),
], 'private-document');
c98(is_array($goodUpload) && empty($goodUpload['delivery_allowed']), 'Valid upload must enter quarantine, not direct delivery.');
$double = $uploads->validate([
    'name' => 'case.jpg.php', 'size' => 1024, 'declared_mime' => 'image/jpeg',
    'detected_mime' => 'image/jpeg', 'sha256' => str_repeat('a', 64),
], 'private-document');
c98(is_wp_error($double), 'Executable/double-extension upload must fail.');
$scan = $uploads->scannerResult(['status' => 'clean', 'engine' => 'scanner-v1', 'scanned_at' => gmdate('c'), 'evidence_ref' => 'scan:result-01']);
c98(is_array($scan) && ! empty($scan['delivery_allowed']), 'Only clean evidenced scan may permit delivery.');

$delivery = new PrivateDeliveryPolicy();
$authorizer = static fn (int $user, string $asset, string $purpose): bool => $user === 7 && $asset === 'asset:private-01' && $purpose === 'patient-authorized-view';
$grant = $delivery->issue(7, 'asset:private-01', 'patient-authorized-view', 60, $authorizer);
c98(is_array($grant), 'Native-owner-authorized private grant must issue.');
$consumed = $delivery->consume((string) $grant['grant'], 7, $authorizer);
c98(is_array($consumed) && ($consumed['cache_control'] ?? '') === 'private, no-store, max-age=0', 'Private grant must reauthorize and return no-store policy.');
$consumedTwice = $delivery->consume((string) $grant['grant'], 7, $authorizer);
c98(is_wp_error($consumedTwice), 'One-time private grant must not replay.');
$writeFailureGrant = $delivery->issue(7, 'asset:private-01', 'patient-authorized-view', 60, $authorizer);
c98(is_array($writeFailureGrant), 'A second private grant must issue for persistence-failure testing.');
$writeFailureToken = substr((string) $writeFailureGrant['grant'], 9);
$writeFailureOption = 'spcrc_delivery_' . substr(hash('sha256', $writeFailureToken), 0, 40);
$GLOBALS['wp_update_option_fail'][$writeFailureOption] = true;
$writeFailure = $delivery->consume((string) $writeFailureGrant['grant'], 7, $authorizer);
c98(is_wp_error($writeFailure) && $writeFailure->get_error_code() === 'spcrc_private_delivery_consume_failed', 'Delivery must fail closed when one-time consumption cannot be persisted.');
unset($GLOBALS['wp_update_option_fail'][$writeFailureOption]);
$writeRecovery = $delivery->consume((string) $writeFailureGrant['grant'], 7, $authorizer);
c98(is_array($writeRecovery) && ! empty($writeRecovery['authorized']), 'Unconsumed grant may recover only after durable persistence is restored.');

$identity = new IdentityAssurance();
$blocked = $identity->authorizeSensitiveAction(7, 'key-rotation');
c98(is_wp_error($blocked) && $blocked->get_error_code() === 'spcrc_identity_authority_unavailable', 'Missing File 00/File 02 authority must fail closed.');
add_filter('spcrc/identity_authority_available', '__return_true');
add_filter('spcrc/authentication_authority_available', '__return_true');
add_filter('spcrc/membership_assertions', static fn (): array => ['approved' => true, 'suspended' => false, 'state' => 'approved', 'guardian_required' => false]);
add_filter('spcrc/authentication_assurance', static fn (): array => ['authenticated' => true, 'recent_authentication' => true, 'mfa_satisfied' => true, 'assurance_ref' => 'auth:recent-01', 'session_risk' => 'low']);
$allowed = $identity->authorizeSensitiveAction(7, 'key-rotation');
c98(is_array($allowed) && ! empty($allowed['authorized']), 'Combined membership/authentication assurance must authorize eligible action.');

c98(count(BoundaryPolicyCatalog::all()) === 6, 'Six high-risk boundary policy domains must exist.');
$clinical = BoundaryPolicyCatalog::get('clinical');
$verified = BoundaryPolicyCatalog::evaluate('clinical', [
    'controls' => $clinical['required_controls'], 'evidence_ref' => 'test:clinical-controls', 'tested_at' => gmdate('c'),
]);
c98(($verified['state'] ?? '') === 'verified' && ! empty($verified['write_allowed']), 'Complete clinical boundary evidence may verify the contract.');
$incomplete = BoundaryPolicyCatalog::evaluate('ai', ['controls' => ['source_citation']]);
c98(($incomplete['state'] ?? '') === 'incomplete' && empty($incomplete['write_allowed']), 'Incomplete AI boundary evidence must block write assurance.');

echo "PASS: $count Cycle 98 security-boundary completion assertions\n";
