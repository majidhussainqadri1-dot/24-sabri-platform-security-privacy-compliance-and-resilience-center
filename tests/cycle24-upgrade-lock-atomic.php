<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/AtomicOptionLock.php';

use Sabri\Platform\Security\Support\AtomicOptionLock;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    ++$assertions;
};

$name = 'spcrc_upgrade_lock';
$GLOBALS['wp_options'][$name] = ['token' => 'active-upgrade', 'expires_at' => time() + 60];
$active = AtomicOptionLock::acquire($name, 120);
$assert(is_wp_error($active) && $active->get_error_code() === 'spcrc_atomic_lock_contended', 'Active upgrade lock must remain owned by the current worker.');
$assert(($GLOBALS['wp_options'][$name]['token'] ?? '') === 'active-upgrade', 'Contending worker must not delete the active upgrade lock.');

$GLOBALS['wp_options'][$name] = ['token' => 'expired-upgrade', 'expires_at' => time() - 1];
$reclaimed = AtomicOptionLock::acquire($name, 120);
$assert(is_string($reclaimed) && $reclaimed !== '', 'Expired upgrade lock must be atomically reclaimed.');
$assert(($GLOBALS['wp_options'][$name]['token'] ?? '') === $reclaimed, 'Reclaimed lock must store the new owner token.');
$assert(AtomicOptionLock::owned($name, $reclaimed), 'New upgrade owner must be verifiable.');
$assert(! AtomicOptionLock::release($name, 'foreign-token'), 'Foreign token must not release the upgrade lock.');
$assert(array_key_exists($name, $GLOBALS['wp_options']), 'Foreign release attempt must preserve the lock.');
$assert(AtomicOptionLock::release($name, $reclaimed), 'Exact owner token must release the upgrade lock.');
$assert(! array_key_exists($name, $GLOBALS['wp_options']), 'Released upgrade lock must be removed.');

$GLOBALS['wp_options'][$name] = ['expires_at' => time() - 1];
$malformed = AtomicOptionLock::acquire($name, 120);
$assert(is_wp_error($malformed) && $malformed->get_error_code() === 'spcrc_atomic_lock_malformed', 'Malformed upgrade lock must fail closed.');
$assert(array_key_exists($name, $GLOBALS['wp_options']), 'Malformed lock evidence must not be overwritten.');

echo "PASS: {$assertions} Cycle 24 atomic upgrade-lock assertions\n";
