<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/GovernanceRepository.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/RiskRepository.php';

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\RiskRepository;

$assertions = 0;
function expectCycle38(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps']['spcrc_accept_critical_risk'] = true;
$governance = new GovernanceRepository(new AuditLogger());
$decision = '38383838-3838-4383-8383-383838383838';
$risk = '38383838-3838-4383-8383-383838383839';
$GLOBALS['wpdb']->governance[$decision] = [
    'decision_uuid' => $decision,
    'decision_type' => 'critical-risk-acceptance',
    'subject_key' => $risk,
    'module_key' => 'file-24-security-center',
    'status' => 'approved',
    'requester_user_id' => 7,
    'approver_user_id' => 8,
    'evidence_ref' => 'case:cycle38',
    'rationale_hash' => hash('sha256', 'reason'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 120),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => gmdate('Y-m-d H:i:s', time() - 60),
    'revoked_at' => null,
    'lock_version' => 1,
];
$base = [
    'risk_uuid' => $risk,
    'module_key' => 'file-24-security-center',
    'title' => 'Cycle 38 optimistic concurrency',
    'status' => 'open',
    'treatment' => 'mitigate',
    'governance_decision_uuid' => null,
    'accepted_by_user_id' => null,
    'accepted_at' => null,
    'acceptance_expires_at' => null,
    'updated_at' => gmdate('Y-m-d H:i:s', time() - 30),
];
$GLOBALS['wpdb']->risks[$risk] = $base;
$repo = new RiskRepository(new AuditLogger(), $governance);
$GLOBALS['wpdb']->stealRiskVersionOnUpdate = true;
$result = $repo->acceptRisk($risk, $decision);
expectCycle38(is_wp_error($result), 'A same-status concurrent risk edit must block acceptance.');
expectCycle38($result->get_error_code() === 'spcrc_risk_concurrent_change', 'Concurrent risk edit must return the dedicated error.');
expectCycle38(($GLOBALS['wpdb']->risks[$risk]['status'] ?? '') === 'open', 'Concurrent edit must not be overwritten by acceptance.');
expectCycle38(($GLOBALS['wpdb']->risks[$risk]['treatment'] ?? '') === 'mitigate', 'Concurrent edit must preserve treatment.');

$GLOBALS['wpdb']->risks[$risk] = $base;
$GLOBALS['wpdb']->failAuditInsert = true;
$GLOBALS['wpdb']->mutateAcceptedRiskBeforeRollback = true;
$result = $repo->acceptRisk($risk, $decision);
expectCycle38(is_wp_error($result), 'Audit failure must fail risk acceptance.');
expectCycle38($result->get_error_code() === 'spcrc_risk_acceptance_audit_failed', 'Audit failure must keep its public failure contract.');
expectCycle38(($GLOBALS['wpdb']->risks[$risk]['status'] ?? '') === 'accepted', 'Rollback must not clobber a concurrently changed accepted row.');
expectCycle38(AuditGapStore::count('spcrc_risk_audit_gap') === 1, 'Failed exact rollback must create a durable risk audit gap.');
expectCycle38(($GLOBALS['wpdb']->risks[$risk]['accepted_at'] ?? '') !== null, 'Concurrent accepted-row evidence must be retained.');

printf("PASS: %d Cycle 38 risk optimistic-concurrency assertions\n", $assertions);
