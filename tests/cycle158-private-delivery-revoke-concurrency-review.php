<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\PrivateDeliveryPolicy;
use Sabri\Platform\Security\Support\AtomicOptionLock;

function c158(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$policy = new PrivateDeliveryPolicy();
$authorizer = static fn (int $userId, string $assetRef, string $purpose): bool => $userId === 7 && $assetRef === 'asset:cycle158' && $purpose === 'private-download';
$issued = $policy->issue(7, 'asset:cycle158', 'private-download', 300, $authorizer);
c158(! is_wp_error($issued), 'Private delivery grant must be issued for concurrency review.');
$grant = (string) $issued['grant'];
$token = substr($grant, 9);
$hash = hash('sha256', $token);
$option = 'spcrc_delivery_' . substr($hash, 0, 40);
$lockOption = 'spcrc_private_delivery_consume_lock_' . substr($hash, 0, 32);

$held = AtomicOptionLock::acquire($lockOption, 30);
c158(! is_wp_error($held), 'Test must acquire the same per-grant coordination lock used by consume/revoke.');
c158($policy->revoke($grant) === false, 'Revocation must fail closed while grant consumption owns the per-grant lock.');
c158(isset($GLOBALS['wp_options'][$option]), 'Contended revocation must not delete or mutate grant state behind an active consumer.');
AtomicOptionLock::release($lockOption, $held);

c158($policy->revoke($grant) === true, 'Revocation must succeed only after exclusive ownership of the per-grant lock is obtained.');
c158(! isset($GLOBALS['wp_options'][$option]), 'Successful revocation must durably remove the grant.');
$consumed = $policy->consume($grant, 7, $authorizer);
c158(is_wp_error($consumed) && $consumed->get_error_code() === 'spcrc_private_delivery_expired', 'Revoked grant must not be resurrected by a later consume attempt.');

echo "PASS: cycle158 private-delivery consume/revoke concurrency defect fixed and retested\n";
