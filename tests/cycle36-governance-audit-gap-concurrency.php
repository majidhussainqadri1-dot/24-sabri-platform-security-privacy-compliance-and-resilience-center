<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/GovernanceRepository.php';

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;

$assertions = 0;
function expectCycle36(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

add_filter('spcrc/verify_step_up_assurance', static fn (): bool => true, 10, 4);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$uuid = '36363636-3636-4363-8363-363636363636';
$GLOBALS['wpdb']->governance[$uuid] = [
    'decision_uuid' => $uuid,
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle36-subject',
    'module_key' => 'file-24-security-center',
    'status' => 'pending',
    'requester_user_id' => 99,
    'approver_user_id' => null,
    'evidence_ref' => 'case:cycle36',
    'rationale_hash' => hash('sha256', 'reason'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 60),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => null,
    'revoked_at' => null,
    'lock_version' => 0,
];

$GLOBALS['wp_options']['spcrc_governance_audit_gap_lock'] = ['token' => 'other-gap-writer', 'expires_at' => time() + 60];
$GLOBALS['wpdb']->failAuditInsert = true;
$repo = new GovernanceRepository(new AuditLogger());
$result = $repo->decide($uuid, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'step:cycle36',
    'note' => 'A bounded approval note.',
]);

expectCycle36(is_wp_error($result), 'Decision audit failure must remain an error.');
expectCycle36($result->get_error_code() === 'spcrc_governance_audit_gap', 'Stored decision without audit must require reconciliation.');
expectCycle36(($GLOBALS['wpdb']->governance[$uuid]['status'] ?? '') === 'approved', 'Decision row must reflect the stored but unusable outcome.');
expectCycle36(AuditGapStore::count('spcrc_governance_batch_audit_gap') === 1, 'Specific-gap lock contention must create a durable generic fallback gap.');
expectCycle36($repo->hasAuditGap($uuid), 'Fallback gap must make the exact decision fail closed.');
expectCycle36(! $repo->isApprovedFor($uuid, 'policy-exception', 'cycle36-subject'), 'A decision with only fallback gap evidence must not authorize use.');
expectCycle36(get_option('spcrc_governance_audit_gap', []) === [], 'Contended specific registry must not be mutated without ownership.');

printf("PASS: %d Cycle 36 governance audit-gap concurrency assertions\n", $assertions);
