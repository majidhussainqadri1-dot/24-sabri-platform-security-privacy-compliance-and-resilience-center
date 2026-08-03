<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Storage/Schema.php';
require_once $base . 'Storage/AuditLogger.php';
require_once $base . 'Storage/AuditGapStore.php';

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

$assertions = 0;
function expectCycle20(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$option = 'spcrc_risk_audit_gap';
expectCycle20(AuditGapStore::record($option, 'risk_uuid', 'risk-one', 'audit_write_failed'), 'The first audit gap must persist.');
expectCycle20(AuditGapStore::record($option, 'risk_uuid', 'risk-two', 'audit_write_failed'), 'The second audit gap must persist.');
expectCycle20(AuditGapStore::count($option) === 2, 'Sequential mutations must preserve both independent gaps.');
expectCycle20(get_option('spcrc_audit_gap_store_lock', false) === false, 'A successful record must release its atomic lock.');

$before = AuditGapStore::all($option);
update_option('spcrc_audit_gap_store_lock', ['token' => 'other-owner', 'expires_at' => time() + 30], false);
$contendedRecord = AuditGapStore::record($option, 'risk_uuid', 'risk-three', 'audit_write_failed');
expectCycle20($contendedRecord === false, 'An active mutation lock must fail a competing record closed.');
expectCycle20(AuditGapStore::all($option) === $before, 'A contended record must not overwrite or truncate existing gaps.');
$lastAction = $GLOBALS['wp_actions'][array_key_last($GLOBALS['wp_actions'])] ?? [];
expectCycle20(($lastAction[0] ?? '') === 'spcrc/audit_gap_lock_failed', 'Lock contention must emit an observable operational action.');
delete_option('spcrc_audit_gap_store_lock');

update_option('spcrc_audit_gap_store_lock', ['token' => 'expired-owner', 'expires_at' => time() - 1], false);
expectCycle20(AuditGapStore::record($option, 'risk_uuid', 'risk-three', 'audit_write_failed'), 'An expired orphan lock must be reclaimed.');
expectCycle20(AuditGapStore::count($option) === 3, 'Stale-lock recovery must preserve prior gaps and append the new gap.');
expectCycle20(get_option('spcrc_audit_gap_store_lock', false) === false, 'Stale-lock recovery must release the replacement lock.');

add_filter('spcrc/verify_step_up_assurance', static fn (mixed $current): bool => true, 10, 5);
$gapId = (string) array_key_first(AuditGapStore::all($option));
update_option('spcrc_audit_gap_store_lock', ['token' => 'reconcile-owner', 'expires_at' => time() + 30], false);
$contendedReconcile = AuditGapStore::reconcile($option, $gapId, 'vault:cycle20-proof', 'file00:cycle20-stepup', new AuditLogger());
expectCycle20(is_wp_error($contendedReconcile), 'A reconciliation competing with a live mutation must fail closed.');
expectCycle20($contendedReconcile->get_error_code() === 'spcrc_audit_gap_lock_unavailable', 'Contended reconciliation must use the canonical lock error.');
expectCycle20(isset(AuditGapStore::all($option)[$gapId]), 'Contended reconciliation must not remove evidence.');
delete_option('spcrc_audit_gap_store_lock');

$reconciled = AuditGapStore::reconcile($option, $gapId, 'vault:cycle20-proof', 'file00:cycle20-stepup', new AuditLogger());
expectCycle20($reconciled === true, 'Reconciliation must succeed after lock ownership becomes available.');
expectCycle20(! isset(AuditGapStore::all($option)[$gapId]), 'Successful reconciliation must remove only the selected gap.');
expectCycle20(AuditGapStore::count($option) === 2, 'Successful reconciliation must preserve other gap records.');
expectCycle20(get_option('spcrc_audit_gap_store_lock', false) === false, 'Successful reconciliation must release its lock.');

$reflection = new ReflectionClass(AuditGapStore::class);
$release = $reflection->getMethod('releaseLock');
$release->setAccessible(true);
update_option('spcrc_audit_gap_store_lock', ['token' => 'rightful-owner', 'expires_at' => time() + 30], false);
$release->invoke(null, 'wrong-owner');
expectCycle20(get_option('spcrc_audit_gap_store_lock', false) !== false, 'A non-owner must not release another mutation lock.');
$release->invoke(null, 'rightful-owner');
expectCycle20(get_option('spcrc_audit_gap_store_lock', false) === false, 'The matching owner token must release the lock.');

$source = (string) file_get_contents($base . 'Storage/AuditGapStore.php');
expectCycle20(str_contains($source, "private const LOCK_OPTION = 'spcrc_audit_gap_store_lock';"), 'Audit-gap mutation must use one canonical atomic lock option.');
expectCycle20(substr_count($source, 'self::acquireLock()') === 2, 'Both record and reconcile mutations must acquire the lock.');
expectCycle20(substr_count($source, 'self::releaseLock($lock)') === 2, 'Both mutation paths must release their owned lock in finally blocks.');
expectCycle20(str_contains($source, 'add_option(self::LOCK_OPTION'), 'Lock acquisition must use atomic add_option semantics.');
expectCycle20(str_contains($source, "hash_equals((string) (\$existing['token'] ?? ''), \$token)"), 'Lock release must be owner-token bound.');

echo "PASS: {$assertions} Cycle 20 audit-gap concurrency assertions\n";
