<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/FindingRepository.php';

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\FindingRepository;

$assertions = 0;
function expectCycle39(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$uuid = '39393939-3939-4393-8393-393939393939';
$base = [
    'finding_uuid' => $uuid,
    'module_key' => 'file-24-security-center',
    'title' => 'Cycle 39 concurrency finding',
    'severity' => 'high',
    'status' => 'open',
    'owner_user_id' => 7,
    'due_at' => null,
    'evidence_ref' => 'case:cycle39',
    'governance_decision_uuid' => null,
    'acceptance_expires_at' => null,
    'created_at' => gmdate('Y-m-d H:i:s', time() - 60),
    'updated_at' => gmdate('Y-m-d H:i:s', time() - 30),
];
$GLOBALS['wpdb']->findings[$uuid] = $base;
$repo = new FindingRepository(new AuditLogger());
$GLOBALS['wpdb']->stealFindingVersionOnUpdate = true;
$result = $repo->setStatus($uuid, 'triaged', [
    'expected_status' => 'open',
    'note' => 'Bounded triage accountability note.',
]);
expectCycle39(is_wp_error($result), 'A same-status concurrent finding edit must block transition.');
expectCycle39($result->get_error_code() === 'spcrc_finding_concurrent_change', 'Concurrent finding edit must return the dedicated error.');
expectCycle39(($GLOBALS['wpdb']->findings[$uuid]['status'] ?? '') === 'open', 'Concurrent finding edit must not be overwritten.');

$GLOBALS['wpdb']->findings[$uuid] = $base;
$GLOBALS['wpdb']->failAuditInsert = true;
$GLOBALS['wpdb']->mutateFindingBeforeRollback = true;
$result = $repo->setStatus($uuid, 'triaged', [
    'expected_status' => 'open',
    'note' => 'Bounded audit rollback test note.',
]);
expectCycle39(is_wp_error($result), 'Audit failure must fail the status transition.');
expectCycle39($result->get_error_code() === 'spcrc_finding_status_audit_failed', 'Finding audit failure contract must remain stable.');
expectCycle39(($GLOBALS['wpdb']->findings[$uuid]['status'] ?? '') === 'triaged', 'Exact rollback must not clobber a concurrently changed transitioned row.');
expectCycle39(AuditGapStore::count('spcrc_finding_audit_gap') === 1, 'Failed exact finding rollback must create a durable audit gap.');
expectCycle39(($GLOBALS['wpdb']->findings[$uuid]['updated_at'] ?? '') !== $base['updated_at'], 'Concurrent finding version must be retained.');

printf("PASS: %d Cycle 39 finding optimistic-concurrency assertions\n", $assertions);
