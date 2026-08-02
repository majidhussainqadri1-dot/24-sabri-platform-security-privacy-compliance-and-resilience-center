<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Storage/AuditLogger.php',
    'Storage/GovernanceRepository.php',
    'Storage/RiskRepository.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\RiskRepository;

$assertions = 0;
function expectGovernance(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$governance = new GovernanceRepository(new AuditLogger());
$governance->registerHooks();

$badEvidence = $governance->request([
    'decision_type' => 'critical-risk-acceptance',
    'subject_key' => 'risk-one',
    'module_key' => 'file-24-security-center',
    'evidence_ref' => 'https://private.example/evidence',
    'rationale' => 'Bounded business reason.',
]);
expectGovernance(is_wp_error($badEvidence) && $badEvidence->get_error_code() === 'spcrc_governance_evidence_invalid', 'Raw evidence URL must be rejected.');

$decision = $governance->request([
    'decision_type' => 'policy-exception',
    'subject_key' => 'policy-exception-one',
    'module_key' => 'file-24-security-center',
    'evidence_ref' => 'vault:policy-exception-one',
    'rationale' => 'Time-bounded exception pending independent approval.',
    'expires_at' => gmdate('c', time() + 7200),
]);
expectGovernance(is_string($decision), 'Valid governance request must persist.');
expectGovernance($governance->pendingCount() === 1, 'Pending decision count must be available.');

$duplicate = $governance->request([
    'decision_type' => 'policy-exception',
    'subject_key' => 'policy-exception-one',
    'module_key' => 'file-24-security-center',
    'evidence_ref' => 'vault:policy-exception-two',
    'rationale' => 'Duplicate request.',
]);
expectGovernance(is_wp_error($duplicate) && $duplicate->get_error_code() === 'spcrc_governance_duplicate_pending', 'Duplicate active request must fail closed.');

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$sameActor = $governance->decide($decision, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'assertion:step-up-one',
    'note' => 'Approved after review.',
]);
expectGovernance(is_wp_error($sameActor) && $sameActor->get_error_code() === 'spcrc_governance_separation_failed', 'Requester must not approve own decision.');

$GLOBALS['current_user_id'] = 8;
add_filter('spcrc/verify_step_up_assurance', static fn (bool $current, int $userId, string $purpose, string $reference): bool => $userId === 8 && str_starts_with($purpose, 'governance:') && $reference === 'assertion:step-up-one', 10, 4);
$stale = $governance->decide($decision, 'approved', [
    'expected_lock_version' => 1,
    'step_up_reference' => 'assertion:step-up-one',
    'note' => 'Approved after review.',
]);
expectGovernance(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_governance_stale_decision', 'Stale governance approval must fail.');
expectGovernance($governance->decide($decision, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'assertion:step-up-one',
    'note' => 'Approved after independent review.',
]) === true, 'Independent step-up approval must succeed.');
expectGovernance($governance->isApprovedFor($decision, 'policy-exception', 'policy-exception-one'), 'Approved decision must be type/subject bound.');
expectGovernance(! $governance->isApprovedFor($decision, 'policy-exception', 'another-subject'), 'Approved decision must not be replayable to another subject.');

// Risk acceptance must be separately requested and approved after the risk exists.
$GLOBALS['current_user_id'] = 7;
unset($GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$riskRepo = new RiskRepository(new AuditLogger(), $governance);
$blockedCreate = $riskRepo->create([
    'title' => 'Premature acceptance',
    'module_key' => 'file-17-communication-network',
    'treatment' => 'accept',
]);
expectGovernance(is_wp_error($blockedCreate) && $blockedCreate->get_error_code() === 'spcrc_risk_acceptance_decision_required', 'Risk cannot be accepted at creation.');
$risk = $riskRepo->create([
    'title' => 'Provider residual risk',
    'module_key' => 'file-17-communication-network',
    'likelihood' => 2,
    'impact' => 4,
    'treatment' => 'mitigate',
]);
expectGovernance(is_string($risk), 'Risk must be recorded before acceptance.');
$riskDecision = $governance->request([
    'decision_type' => 'critical-risk-acceptance',
    'subject_key' => $risk,
    'module_key' => 'file-17-communication-network',
    'evidence_ref' => 'vault:risk-acceptance-one',
    'rationale' => 'Residual risk is time-bounded and has a compensating control.',
]);
expectGovernance(is_string($riskDecision), 'Risk acceptance decision request must persist.');

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
expectGovernance($governance->decide($riskDecision, 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'assertion:step-up-one',
    'note' => 'Residual risk accepted for the documented window.',
]) === true, 'Risk governance decision must be independently approved.');
$GLOBALS['current_user_caps']['spcrc_accept_critical_risk'] = true;
expectGovernance($riskRepo->acceptRisk($risk, $riskDecision) === true, 'Risk acceptance must bind the approved governance decision.');
expectGovernance(($GLOBALS['wpdb']->risks[$risk]['governance_decision_uuid'] ?? '') === $riskDecision, 'Risk record must retain governance binding.');
$GLOBALS['wpdb']->risks[$risk]['acceptance_expires_at'] = gmdate('Y-m-d H:i:s', time() - 60);
expectGovernance($riskRepo->reopenExpiredAcceptances() === 1 && ($GLOBALS['wpdb']->risks[$risk]['status'] ?? '') === 'open', 'Expired risk acceptance must automatically reopen.');

$GLOBALS['wp_options']['spcrc_governance_audit_gap'] = ['decision_uuid' => $decision];
expectGovernance(! $governance->isApprovedFor($decision, 'policy-exception', 'policy-exception-one'), 'Unreconciled audit gap must invalidate decision use.');

echo "PASS: {$assertions} governance, separation-of-duties and risk-acceptance assertions\n";
