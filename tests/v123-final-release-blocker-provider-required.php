<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;

function assertV123FinalProvider(bool $condition, string $message): void
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
$artifacts = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($artifacts);
$gates->seed();
$phases = ReleaseGateManager::phases();
$context = [
    'step_up_reference' => 'assertion:v123-final-registered-stepup',
    'approval_refs' => ['approval:v123-final-person-one', 'approval:v123-final-person-two'],
];

// Repository-only phases preserve their existing authorization semantics and
// do not masquerade as evidence of actual staging or production operation.
foreach (array_slice($phases, 0, -1) as $index => $phase) {
    $result = $gates->decide(
        $phase, 'passed', 1, 'evidence:v123-source-phase-' . $index,
        ['Repository phase has distinct evidentiary requirements'], $context
    );
    assertV123FinalProvider(is_string($result), 'Historical repository phase ' . $index . ' must remain compatible.');
}

$finalPhase = $phases[count($phases) - 1];
$final = static fn () => $gates->decide(
    $finalPhase, 'passed', 1, 'evidence:v123-final-staging',
    ['Independent acceptance evidence must be valid'], $context
);

// Without a configured authoritative provider, WordPress apply_filters()
// defaults to zero; the final release must not interpret zero as verified.
$missing = $final();
assertV123FinalProvider(
    is_wp_error($missing) && $missing->get_error_code() === 'spcrc_release_gate_blocker_provider_missing',
    'Final gate must reject missing blocker-count providers.'
);
assertV123FinalProvider(
    ($artifacts->get('release-gate', $finalPhase)['status'] ?? '') === 'pending',
    'Missing provider must not mutate the final gate.'
);

add_filter('spcrc/release_blocking_p0_count', static fn (): int => 0, 10, 2);
$half = $final();
assertV123FinalProvider(
    is_wp_error($half) && $half->get_error_code() === 'spcrc_release_gate_blocker_provider_missing',
    'One present filter cannot conceal the other missing provider.'
);

add_filter('spcrc/release_blocking_defect_count', static fn (): int => 0, 10, 3);
$external = $final();
assertV123FinalProvider(
    is_wp_error($external) && $external->get_error_code() === 'spcrc_release_gate_external_acceptance_missing',
    'Both providers alone are not sufficient; independent staging acceptance is separate.'
);

add_filter('spcrc/release_external_acceptance_ready', '__return_true', 10, 3);
$ready = $final();
assertV123FinalProvider(is_string($ready), 'Only explicitly provided zero-defect evidence plus external acceptance can pass.');
assertV123FinalProvider(
    ($artifacts->get('release-gate', $finalPhase)['status'] ?? '') === 'passed',
    'Approved final decision should be recorded.'
);
echo "PASS: V12.3 final phase refuses missing blocker providers and still requires external assurance\n";
