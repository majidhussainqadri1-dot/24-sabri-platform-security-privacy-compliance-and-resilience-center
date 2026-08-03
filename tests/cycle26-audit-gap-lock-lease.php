<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditGapStore.php';

use Sabri\Platform\Security\Storage\AuditGapStore;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    ++$assertions;
};

$source = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditGapStore.php');
$assert(str_contains($source, 'AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL)'), 'Audit-gap store must use exact-value atomic acquisition.');
$assert(substr_count($source, 'AtomicOptionLock::refresh(self::LOCK_OPTION, $lock, self::LOCK_TTL)') === 2, 'Record and reconcile must renew ownership before commit.');
$assert(str_contains($source, "'spcrc_audit_gap_lock_lost'"), 'Reconciliation must expose lost ownership explicitly.');
$assert(str_contains($source, "'spcrc/audit_gap_lock_lost'"), 'Record lock loss must emit operational evidence.');
$assert(str_contains($source, 'AtomicOptionLock::release(self::LOCK_OPTION, $token)'), 'Release must use exact owner-token comparison.');

$option = 'spcrc_incident_audit_gap';
$GLOBALS['wp_options']['spcrc_audit_gap_store_lock'] = ['token' => 'active-writer', 'expires_at' => time() + 30];
$before = AuditGapStore::all($option);
$assert(! AuditGapStore::record($option, 'incident_uuid', 'incident-1', 'audit_failed'), 'Active lock must block a competing audit-gap write.');
$assert(AuditGapStore::all($option) === $before, 'Blocked write must not change audit-gap evidence.');
$assert(($GLOBALS['wp_options']['spcrc_audit_gap_store_lock']['token'] ?? '') === 'active-writer', 'Competing writer must preserve the active owner lock.');

$GLOBALS['wp_options']['spcrc_audit_gap_store_lock'] = ['token' => 'expired-writer', 'expires_at' => time() - 1];
$assert(AuditGapStore::record($option, 'incident_uuid', 'incident-1', 'audit_failed'), 'Expired lock must be reclaimed atomically.');
$assert(AuditGapStore::count($option) === 1, 'Reclaimed write must persist one bounded gap.');
$assert(get_option('spcrc_audit_gap_store_lock', false) === false, 'Exact owner must release the reclaimed lock.');

$GLOBALS['wp_options']['spcrc_audit_gap_store_lock'] = ['expires_at' => time() - 1];
$assert(! AuditGapStore::record($option, 'incident_uuid', 'incident-2', 'audit_failed'), 'Malformed lock must fail closed.');
$assert(AuditGapStore::count($option) === 1, 'Malformed-lock failure must preserve existing evidence.');

echo "PASS: {$assertions} Cycle 26 audit-gap lock/lease assertions\n";
