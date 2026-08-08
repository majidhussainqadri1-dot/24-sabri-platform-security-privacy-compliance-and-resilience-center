<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use Sabri\Platform\Security\Security\PrivateDeliveryPolicy;
use Sabri\Platform\Security\Support\AtomicOptionLock;
function c134(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }
$policy = new PrivateDeliveryPolicy();
$auth = static fn (int $user, string $asset, string $purpose): bool => $user === 7 && $asset === 'asset:cycle134' && $purpose === 'private-view';
$issued = $policy->issue(7, 'asset:cycle134', 'private-view', 60, $auth);
c134(is_array($issued), 'Private delivery grant must issue.');
$token = substr((string) $issued['grant'], 9);
$hash = hash('sha256', $token);
$consumeLock = 'spcrc_private_delivery_consume_lock_' . substr($hash, 0, 32);
$held = AtomicOptionLock::acquire($consumeLock, 30);
c134(is_string($held), 'Test must acquire the same per-grant consume lock.');
$contended = $policy->consume((string) $issued['grant'], 7, $auth);
c134(is_wp_error($contended) && $contended->get_error_code() === 'spcrc_private_delivery_consume_contended', 'Concurrent consume attempt must fail before one-time state is read/updated.');
c134(AtomicOptionLock::release($consumeLock, $held), 'Test contention lock must release cleanly.');
$first = $policy->consume((string) $issued['grant'], 7, $auth);
c134(is_array($first) && ! empty($first['authorized']), 'Grant must remain usable after contention clears.');
$second = $policy->consume((string) $issued['grant'], 7, $auth);
c134(is_wp_error($second), 'One-time grant must still reject replay after successful consume.');
echo "PASS: cycle134 private-delivery consumption race defect fixed and retested\n";
