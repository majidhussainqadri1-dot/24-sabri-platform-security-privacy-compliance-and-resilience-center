<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;

function assertP0Waiver(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_release_gates' => true,
    'spcrc_approve_governance_decision' => true,
];
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
add_filter('spcrc/verify_founder_risk_acceptance', '__return_true', 10, 4);
add_filter('spcrc/release_blocking_p0_count', static fn (): int => 1, 10, 2);

$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();
$phase = ReleaseGateManager::phases()[0];

$waiver = $gates->decide($phase, 'waived', 1, 'evidence:p0-waiver-test', ['Founder-approved exception'], [
    'step_up_reference' => 'assertion:p0-waiver-stepup',
    'approval_refs' => ['approval:p0-first-person', 'approval:p0-second-person'],
    'risk_acceptance_reference' => 'risk-acceptance:founder-p0-waiver',
]);

assertP0Waiver(is_wp_error($waiver), 'A P0 defect must block even a fully approved waiver.');
assertP0Waiver($waiver->get_error_code() === 'spcrc_release_gate_p0_blocked', 'P0 waiver denial must have a stable error code.');
$state = $registry->get('release-gate', $phase);
assertP0Waiver(is_array($state) && ($state['status'] ?? '') === 'pending', 'A blocked waiver must not mutate the release gate.');

echo "PASS: launch-critical P0 security blockers are nonwaivable\n";
