<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;

function c192(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$repo = new GovernanceRepository(new AuditLogger());

$negativeRequester = $repo->request([
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle192-negative-requester',
    'evidence_ref' => 'evidence:cycle192-requester',
    'rationale' => 'Must remain bound to the authenticated requester.',
    'requester_user_id' => -7,
]);
c192(is_wp_error($negativeRequester) && $negativeRequester->get_error_code() === 'spcrc_governance_requester_invalid', 'Negative requester ID must not be absint-coerced into authenticated user 7.');

$badExpiry = $repo->request([
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle192-expiry',
    'evidence_ref' => 'evidence:cycle192-expiry',
    'rationale' => 'Malformed explicit expiry must not acquire the implicit seven-day default.',
    'expires_at' => 'next Thursday at noon',
]);
c192(is_wp_error($badExpiry) && $badExpiry->get_error_code() === 'spcrc_governance_expiry_invalid', 'Malformed explicit expiry must fail closed instead of silently becoming a default seven-day decision.');

$decision = $repo->request([
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle192-lock',
    'evidence_ref' => 'evidence:cycle192-lock',
    'rationale' => 'Strict optimistic-version review.',
    'expires_at' => gmdate('c', time() + 3600),
]);
c192(is_string($decision), 'Governance decision fixture must persist.');
$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
add_filter('spcrc/verify_step_up_assurance', static fn (): bool => true, 10, 4);
$negativeLock = $repo->decide($decision, 'approved', [
    'expected_lock_version' => -1,
    'step_up_reference' => 'stepup:cycle192',
    'note' => 'This malformed version must not become version one or zero.',
]);
c192(is_wp_error($negativeLock) && $negativeLock->get_error_code() === 'spcrc_governance_expected_lock_version_invalid', 'Negative expected lock version must be rejected before comparison, not normalized by absint.');
$malformedLock = $repo->decide($decision, 'approved', [
    'expected_lock_version' => '0version',
    'step_up_reference' => 'stepup:cycle192',
    'note' => 'Malformed numeric strings must remain invalid.',
]);
c192(is_wp_error($malformedLock) && $malformedLock->get_error_code() === 'spcrc_governance_expected_lock_version_invalid', 'Malformed optimistic lock version must fail structural validation.');
c192($repo->decide($decision, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'stepup:cycle192',
    'note' => 'Valid independent approval remains supported.',
]) === true, 'Valid exact expected lock version must remain approvable after hardening.');

echo "PASS: cycle192 governance requester, explicit-expiry and optimistic-lock coercion defects fixed and retested\n";
