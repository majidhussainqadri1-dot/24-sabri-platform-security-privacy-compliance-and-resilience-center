<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\EndpointGuard;
use Sabri\Platform\Security\Security\RateLimiter;
use Sabri\Platform\Security\Support\AtomicOptionLock;

function c157(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$guard = new EndpointGuard(new RateLimiter());
$policy = ['methods' => ['POST'], 'require_auth' => true, 'same_origin' => false, 'require_idempotency' => true];
$request = ['method' => 'POST', 'idempotency_key' => 'idem:cycle157-idempotency'];
$first = $guard->authorize($policy, $request);
c157(! is_wp_error($first), 'First bounded idempotent request must be accepted.');
$duplicate = $guard->authorize($policy, $request);
c157(is_wp_error($duplicate) && $duplicate->get_error_code() === 'spcrc_endpoint_replay_detected', 'Duplicate idempotency key must be blocked during its active lifetime.');
$idemOption = 'spcrc_idempotency_' . substr(hash('sha256', 'endpoint|idem:cycle157-idempotency'), 0, 40);
$GLOBALS['wp_options'][$idemOption]['expires_at'] = time() - 1;
$reclaimed = $guard->authorize($policy, $request);
c157(! is_wp_error($reclaimed), 'Expired idempotency state must be atomically reclaimable instead of becoming a permanent tombstone.');

$secret = str_repeat('s', 32);
$timestamp = time();
$body = '{"cycle":157}';
$signature = hash_hmac('sha256', $timestamp . '.' . $body, $secret);
$resolver = static fn (string $provider): string => $secret;
$webhook = $guard->verifyWebhook('provider-a', $body, $signature, $timestamp, $resolver, 300);
c157(! is_wp_error($webhook), 'First signed webhook must verify.');
$webhookReplay = $guard->verifyWebhook('provider-a', $body, $signature, $timestamp, $resolver, 300);
c157(is_wp_error($webhookReplay) && $webhookReplay->get_error_code() === 'spcrc_webhook_replay_detected', 'Webhook replay must be blocked while the replay claim is active.');
$replayOption = 'spcrc_webhook_seen_' . substr(hash('sha256', 'provider-a|' . $timestamp . '|' . $signature), 0, 40);
$GLOBALS['wp_options'][$replayOption]['expires_at'] = time() - 1;
$webhookReclaimed = $guard->verifyWebhook('provider-a', $body, $signature, $timestamp, $resolver, 300);
c157(! is_wp_error($webhookReclaimed), 'Expired webhook replay state must be atomically reclaimable rather than retained forever.');

$limiter = new RateLimiter();
$checked = $limiter->check('cycle157', 'subject-a', 5, 60);
c157(! is_wp_error($checked), 'Rate-limit state must initialize for reset-concurrency review.');
$salt = wp_salt('auth');
$bucket = substr(hash_hmac('sha256', 'cycle157|subject-a', $salt), 0, 40);
$lockName = 'spcrc_rate_lock_' . $bucket;
$held = AtomicOptionLock::acquire($lockName, 15);
c157(! is_wp_error($held), 'Test must acquire the rate-state coordination lock.');
c157($limiter->reset('cycle157', 'subject-a') === false, 'Rate-limit reset must fail closed while another operation owns the bucket lock.');
c157(isset($GLOBALS['wp_options']['spcrc_rate_' . $bucket]), 'Contended reset must not delete state behind an active rate-limit operation.');
AtomicOptionLock::release($lockName, $held);
c157($limiter->reset('cycle157', 'subject-a') === true, 'Rate-limit reset may delete state after acquiring exclusive bucket ownership.');

echo "PASS: cycle157 expiring replay/idempotency state and rate-limit reset atomicity defects fixed and retested\n";
