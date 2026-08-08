<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function c151(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$GLOBALS['current_user_caps'] = ['spcrc_manage_release_gates' => true];
$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();
$phases = ReleaseGateManager::phases();
c151(count($phases) === 12, 'Twelve governed release phases must remain encoded.');

$blockedStepUp = $gates->decide($phases[0], 'passed', 1, 'evidence:phase-one', ['source frozen'], [
    'approval_refs' => ['approval:one-human', 'approval:two-human'],
]);
c151(is_wp_error($blockedStepUp) && $blockedStepUp->get_error_code() === 'spcrc_release_gate_step_up_required', 'Positive release decision must require fresh step-up assurance.');

add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$oneApproval = $gates->decide($phases[0], 'passed', 1, 'evidence:phase-one', ['source frozen'], [
    'step_up_reference' => 'assertion:release-stepup',
    'approval_refs' => ['approval:one-human'],
]);
c151(is_wp_error($oneApproval) && $oneApproval->get_error_code() === 'spcrc_release_gate_dual_approval_required', 'Positive release decision must require two distinct approval references.');

$phaseTwoEarly = $gates->decide($phases[1], 'passed', 1, 'evidence:phase-two', ['inventory complete'], [
    'step_up_reference' => 'assertion:release-stepup',
    'approval_refs' => ['approval:one-human', 'approval:two-human'],
]);
c151(is_wp_error($phaseTwoEarly) && $phaseTwoEarly->get_error_code() === 'spcrc_release_gate_sequence_blocked', 'A later release phase must not pass before the immediately preceding phase closes.');

$phaseOne = $gates->decide($phases[0], 'passed', 1, 'evidence:phase-one', ['source frozen'], [
    'step_up_reference' => 'assertion:release-stepup',
    'approval_refs' => ['approval:one-human', 'approval:two-human'],
]);
c151(! is_wp_error($phaseOne) && ($registry->get('release-gate', $phases[0])['status'] ?? '') === 'passed', 'Phase one must pass with evidence, step-up and dual control.');

c151(AuditGapStore::record('spcrc_risk_audit_gap', 'risk', 'cycle151', 'test_open_gap'), 'Test must create a managed unresolved audit gap.');
$gapBlocked = $gates->decide($phases[1], 'passed', 1, 'evidence:phase-two', ['inventory complete'], [
    'step_up_reference' => 'assertion:release-stepup',
    'approval_refs' => ['approval:one-human', 'approval:two-human'],
]);
c151(is_wp_error($gapBlocked) && $gapBlocked->get_error_code() === 'spcrc_release_gate_audit_gaps_open', 'Unresolved audit gaps must block positive release progression.');
delete_option('spcrc_risk_audit_gap');

$phaseTwo = $gates->decide($phases[1], 'passed', 1, 'evidence:phase-two', ['inventory complete'], [
    'step_up_reference' => 'assertion:release-stepup',
    'approval_refs' => ['approval:one-human', 'approval:two-human'],
]);
c151(! is_wp_error($phaseTwo), 'Phase two may pass only after sequence, evidence, step-up, dual-control and zero-gap conditions are satisfied.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Release/ReleaseGateManager.php');
c151(is_string($source) && str_contains($source, 'spcrc/release_blocking_p0_count') && str_contains($source, 'spcrc/release_external_acceptance_ready'), 'Release manager must encode P0 and external-assurance gates rather than treating repository evidence as production acceptance.');

echo "PASS: cycle151 release-gate authority, sequence and zero-defect gating defects fixed and retested\n";
