<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Retention/RetentionManager.php';

use Sabri\Platform\Security\Retention\RetentionManager;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    ++$assertions;
};

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Retention/RetentionManager.php');
$assert(is_string($source), 'Retention source must be readable.');
$assert(substr_count($source, 'refreshLock($lock)') >= 3, 'Retention must renew ownership before and between destructive phases.');
$assert(str_contains($source, "'retention_lock_lost'"), 'Lost lock ownership must have an explicit fail-closed result.');
$assert(! str_contains($source, 'delete_option(self::LOCK_OPTION);'), 'Deactivation must not blindly delete an option lock owned by another request.');
$assert(str_contains($source, 'AtomicOptionLock::release(self::LOCK_OPTION, $token)'), 'Release must compare the exact owner token.');

// Helper ownership semantics are covered dynamically here because the
// retention manager deliberately keeps its lock methods private.
$name = 'spcrc_retention_lock';
$token = \Sabri\Platform\Security\Support\AtomicOptionLock::acquire($name, 900);
$assert(is_string($token), 'Retention lock must be acquirable.');
$assert(\Sabri\Platform\Security\Support\AtomicOptionLock::refresh($name, $token, 900), 'Current retention owner must be able to renew the lease.');
$GLOBALS['wp_options'][$name]['token'] = 'replacement-owner';
$assert(! \Sabri\Platform\Security\Support\AtomicOptionLock::refresh($name, $token, 900), 'Displaced retention owner must not renew a replacement lock.');
$assert(! \Sabri\Platform\Security\Support\AtomicOptionLock::release($name, $token), 'Displaced retention owner must not release a replacement lock.');
$assert(($GLOBALS['wp_options'][$name]['token'] ?? '') === 'replacement-owner', 'Replacement owner lock must remain intact.');

echo "PASS: {$assertions} Cycle 25 retention-ownership assertions\n";
