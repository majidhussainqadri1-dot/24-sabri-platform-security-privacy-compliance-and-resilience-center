<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\EndpointGuard;

function c176(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$historical = file_get_contents(__DIR__ . '/cycle157-ephemeral-security-state-atomicity-review.php');
c176(is_string($historical) && str_contains($historical, 'endpoint|user:7|idem:cycle157-idempotency'), 'Historical idempotency expiry regression must follow the current principal-scoped key instead of freezing the superseded global scope.');

$GLOBALS['current_user_id'] = 7;
$guard = new EndpointGuard();
$policy = ['methods'=>['POST'], 'require_auth'=>true, 'same_origin'=>false, 'require_idempotency'=>true];
$request = ['method'=>'POST', 'idempotency_key'=>'idem:cycle176'];
$first = $guard->authorize($policy, $request);
c176(is_array($first), 'Current authenticated principal-scoped idempotency request must succeed.');
$option = 'spcrc_idempotency_' . substr(hash('sha256', 'endpoint|user:7|idem:cycle176'), 0, 40);
c176(isset($GLOBALS['wp_options'][$option]), 'Principal-scoped idempotency state must be stored at the current deterministic key.');
$GLOBALS['wp_options'][$option]['expires_at'] = time() - 1;
c176(is_array($guard->authorize($policy, $request)), 'Expired principal-scoped idempotency state must remain reclaimable after historical QA correction.');

echo "PASS: cycle176 historical idempotency regression brittleness fixed and retested\n";
