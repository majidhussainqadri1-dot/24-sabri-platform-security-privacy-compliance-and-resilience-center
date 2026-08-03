<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AssuranceRepository.php';

use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

$assertions = 0;
function expectCycle40(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['wpdb']->failAuditInsert = true;
$GLOBALS['wpdb']->zeroAssuranceDelete = true;
$repo = new AssuranceRepository(new AuditLogger());
$result = $repo->upsert([
    'record_type' => 'backup',
    'record_key' => 'cycle40-backup',
    'title' => 'Cycle 40 backup assurance',
    'status' => 'scheduled',
    'owner_user_id' => 7,
    'notes' => 'Bounded non-sensitive scheduling note.',
]);

expectCycle40(is_wp_error($result), 'Audit failure must reject assurance creation.');
expectCycle40($result->get_error_code() === 'spcrc_assurance_audit_failed', 'Assurance audit failure contract must remain stable.');
expectCycle40(count($GLOBALS['wpdb']->assurance) === 1, 'A zero-row delete must not be misreported as successful rollback.');
expectCycle40(AuditGapStore::count('spcrc_assurance_audit_gap') === 1, 'Failed assurance rollback must create a durable generic audit gap.');
$gaps = AuditGapStore::all('spcrc_assurance_audit_gap');
$gap = reset($gaps);
expectCycle40(($gap['entity_type'] ?? '') === 'assurance_record', 'Audit gap must preserve bounded assurance entity identity.');
expectCycle40(($gap['reason'] ?? '') === 'assurance_audit_rollback_failed', 'Audit gap must preserve the rollback failure reason.');
expectCycle40(in_array('spcrc_assurance_audit_gap', AuditGapStore::managedOptions(), true), 'Assurance gaps must participate in central reconciliation inventory.');

printf("PASS: %d Cycle 40 assurance rollback assertions\n", $assertions);
