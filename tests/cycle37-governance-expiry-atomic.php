<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/GovernanceRepository.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;

$assertions = 0;
function expectCycle37(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$GLOBALS['current_user_id'] = 8;
add_filter('spcrc/verify_step_up_assurance', static fn (): bool => true, 10, 4);
$uuid = '37373737-3737-4373-8373-373737373737';
$GLOBALS['wpdb']->governance[$uuid] = [
    'decision_uuid' => $uuid,
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle37-subject',
    'module_key' => 'file-24-security-center',
    'status' => 'pending',
    'requester_user_id' => 99,
    'approver_user_id' => null,
    'evidence_ref' => 'case:cycle37',
    'rationale_hash' => hash('sha256', 'reason'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 60),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => null,
    'revoked_at' => null,
    'lock_version' => 0,
];

$repo = new GovernanceRepository(new AuditLogger());
$GLOBALS['wpdb']->expireGovernanceBeforeDecisionUpdate = true;
$result = $repo->decide($uuid, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'step:cycle37',
    'note' => 'Bounded independent approval note.',
]);
expectCycle37(is_wp_error($result), 'An expiry race must not approve the decision.');
expectCycle37($result->get_error_code() === 'spcrc_governance_expired', 'Expiry race must return the dedicated expiry error.');
expectCycle37(($GLOBALS['wpdb']->governance[$uuid]['status'] ?? '') === 'expired', 'Expired request must be atomically denied and marked expired.');
expectCycle37(($GLOBALS['wpdb']->governance[$uuid]['approver_user_id'] ?? null) === null, 'Expired request must not bind an approver.');
expectCycle37($GLOBALS['wpdb']->events === [], 'Expired request must not emit an approval audit event.');

$uuid2 = '37373737-3737-4373-8373-373737373738';
$GLOBALS['wpdb']->governance[$uuid2] = array_merge($GLOBALS['wpdb']->governance[$uuid], [
    'decision_uuid' => $uuid2,
    'subject_key' => 'cycle37-normal',
    'status' => 'pending',
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'lock_version' => 0,
    'approver_user_id' => null,
    'decided_at' => null,
]);
$normal = $repo->decide($uuid2, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'step:cycle37-normal',
    'note' => 'Bounded normal approval note.',
]);
expectCycle37($normal === true, 'A non-expired decision must still succeed.');
expectCycle37(($GLOBALS['wpdb']->governance[$uuid2]['status'] ?? '') === 'approved', 'Normal approval must persist exactly once.');

printf("PASS: %d Cycle 37 governance expiry atomicity assertions\n", $assertions);
