<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;

/**
 * V12.3 / CEN-REL-001: Founder waiver cannot release known active defects.
 * This test deliberately distinguishes a release blocker from residual risk
 * or a safely isolated optional feature outside the active release scope.
 */
function assertV123Gate(bool $condition, string $message): void
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
$GLOBALS['v123_active_defect_count'] = 1;

add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
add_filter('spcrc/verify_founder_risk_acceptance', '__return_true', 10, 4);
add_filter('spcrc/release_blocking_p0_count', static fn (): int => 0, 10, 2);
add_filter('spcrc/release_blocking_defect_count', static fn (): int => $GLOBALS['v123_active_defect_count'], 10, 3);

$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();
$phase = ReleaseGateManager::phases()[0];
$context = [
    'step_up_reference' => 'assertion:v123-step-up',
    'approval_refs' => ['approval:v123-independent-one', 'approval:v123-independent-two'],
    'risk_acceptance_reference' => 'risk-acceptance:v123-founder',
];

foreach (['passed', 'waived', 'not-applicable'] as $status) {
    $decision = $gates->decide($phase, $status, 1, 'evidence:v123-active-defect', [
        'v12.3 requires zero known active defects',
    ], $context);
    assertV123Gate(is_wp_error($decision), "An active known defect must block {$status}.");
    assertV123Gate(
        $decision->get_error_code() === 'spcrc_release_gate_known_defects_blocked',
        "Active-defect error must be stable for {$status}."
    );
    $stored = $registry->get('release-gate', $phase);
    assertV123Gate(
        is_array($stored) && ($stored['status'] ?? '') === 'pending',
        "Blocked {$status} must not mutate the gate."
    );
}

// A non-defect residual risk may still be governed by explicit Founder waiver,
// after the native owner has independently excluded any disabled optional scope.
$GLOBALS['v123_active_defect_count'] = 0;
$waiver = $gates->decide($phase, 'waived', 1, 'evidence:v123-residual-risk', [
    'Residual risk accepted with isolated optional scope off',
], $context);
assertV123Gate(is_string($waiver), 'A duly governed waiver with zero active defects remains possible.');
$record = $registry->get('release-gate', $phase);
assertV123Gate(
    is_array($record) && ($record['status'] ?? '') === 'waived',
    'Successful residual-risk waiver must be recorded.'
);
assertV123Gate(
    ($record['payload']['risk_acceptance_reference_hash'] ?? '') === hash('sha256', $context['risk_acceptance_reference']),
    'Waiver must retain a pseudonymized Founder risk-acceptance receipt.'
);

echo "PASS: V12.3 CEN-REL-001 nonwaivable active defects and residual-risk control\n";
