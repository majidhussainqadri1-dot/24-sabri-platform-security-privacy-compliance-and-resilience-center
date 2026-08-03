<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';

use Sabri\Platform\Security\Support\AtomicOptionLock;

$assertions = 0;
function expectCycle30(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$option = 'spcrc_cycle30_lock';
$GLOBALS['wp_options'][$option] = ['token' => 'expired-owner', 'expires_at' => time() - 1];
$before = $GLOBALS['wp_options'][$option];
expectCycle30(! AtomicOptionLock::refresh($option, 'expired-owner', 60), 'An expired owner must not resurrect an ended lease.');
expectCycle30($GLOBALS['wp_options'][$option] === $before, 'Rejected expired refresh must not mutate lock state.');

$GLOBALS['wp_options'][$option] = ['token' => 'active-owner', 'expires_at' => time() + 30];
expectCycle30(AtomicOptionLock::refresh($option, 'active-owner', 60), 'An active owner must be able to renew its lease.');
expectCycle30(($GLOBALS['wp_options'][$option]['token'] ?? '') === 'active-owner', 'Lease renewal must preserve owner identity.');
expectCycle30((int) ($GLOBALS['wp_options'][$option]['expires_at'] ?? 0) > time() + 30, 'Lease renewal must extend the active expiry.');
expectCycle30(! AtomicOptionLock::refresh($option, 'different-owner', 60), 'A non-owner must not refresh an active lease.');

printf("PASS: %d Cycle 30 expired-lock refresh assertions\n", $assertions);
