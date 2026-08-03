<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';

use Sabri\Platform\Security\Support\AtomicOptionLock;

$assertions = 0;
function expectCycle31(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['wp_uuid_override'] = 'not-a-valid-uuid';
$token = AtomicOptionLock::acquire('spcrc_cycle31_lock', 60);
expectCycle31(! is_wp_error($token), 'Malformed WordPress UUID output must fall back to a strong local token.');
expectCycle31(is_string($token) && preg_match('/^[0-9a-f]{32}$/', $token) === 1, 'Fallback token must be 128-bit lowercase hexadecimal.');
expectCycle31(($GLOBALS['wp_options']['spcrc_cycle31_lock']['token'] ?? '') === $token, 'The validated fallback token must own the stored lock.');
expectCycle31(AtomicOptionLock::owned('spcrc_cycle31_lock', (string) $token), 'Fallback token ownership must be verifiable.');
expectCycle31(AtomicOptionLock::release('spcrc_cycle31_lock', (string) $token), 'Fallback token must release its own lock.');
unset($GLOBALS['wp_uuid_override']);

$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php');
expectCycle31(is_string($source) && str_contains($source, 'catch (\\Throwable $error)'), 'Token generation must convert entropy/provider exceptions into a bounded error instead of a fatal.');

printf("PASS: %d Cycle 31 lock-token generation assertions\n", $assertions);
