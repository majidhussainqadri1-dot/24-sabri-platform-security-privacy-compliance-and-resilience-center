<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\IncidentRepository;

function c161(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

// Release-gate review: "not-applicable" previously bypassed the same evidence,
// step-up and dual-control ceremony that can advance the phase sequence.
$GLOBALS['current_user_caps'] = ['spcrc_manage_release_gates' => true, 'spcrc_approve_governance_decision' => true];
$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();
$phase = ReleaseGateManager::phases()[0];
$naNoEvidence = $gates->decide($phase, 'not-applicable', 1, '', ['not applicable'], []);
c161(is_wp_error($naNoEvidence) && $naNoEvidence->get_error_code() === 'spcrc_release_gate_evidence_missing', 'Not-applicable release decision must not bypass evidence.');
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$naOneApproval = $gates->decide($phase, 'not-applicable', 1, 'evidence:cycle161-na', ['not applicable by governed scope'], [
    'step_up_reference' => 'assertion:cycle161-release-stepup',
    'approval_refs' => ['approval:human-one'],
]);
c161(is_wp_error($naOneApproval) && $naOneApproval->get_error_code() === 'spcrc_release_gate_dual_approval_required', 'Not-applicable release decision must require dual human approval.');
add_filter('spcrc/release_blocking_defect_count', static fn (): int => 2, 10, 3);
$blockedKnownDefects = $gates->decide($phase, 'not-applicable', 1, 'evidence:cycle161-na', ['not applicable by governed scope'], [
    'step_up_reference' => 'assertion:cycle161-release-stepup',
    'approval_refs' => ['approval:human-one', 'approval:human-two'],
]);
c161(is_wp_error($blockedKnownDefects) && $blockedKnownDefects->get_error_code() === 'spcrc_release_gate_known_defects_blocked', 'Known unresolved blocking defects must prevent a non-waiver positive release decision.');
$GLOBALS['wp_filters']['spcrc/release_blocking_defect_count'] = [];

// Critical incident closure review: dual approval alone is insufficient for a
// sensitive irreversible closure; a fresh File 00 step-up is now mandatory.
$GLOBALS['current_user_caps'] = ['spcrc_manage_incidents' => true, 'spcrc_close_critical_incidents' => true];
$incidents = new IncidentRepository(new AuditLogger());
$incidentArtifacts = new GovernedArtifactRegistry(new AuditLogger());
$coordinator = new IncidentCoordinator($incidents, $incidentArtifacts);
$incident = $coordinator->declare([
    'title' => 'Cycle 161 critical incident', 'severity' => 'sev0', 'summary' => 'Privileged security event.',
    'playbook' => 'administrator-takeover', 'evidence_ref' => 'incident:cycle161',
]);
c161(is_string($incident), 'Critical incident must be declared for closure review.');
foreach ([
    ['contained', 'contained'], ['eradicated', 'eradicated'], ['recovering', 'recovering'], ['resolved', 'resolved'],
] as [$state, $reason]) {
    c161($coordinator->advance($incident, $state, $reason, 'incident:cycle161-' . $state) === true, 'Critical incident must advance to ' . $state . '.');
}
$GLOBALS['wp_filters']['spcrc/verify_step_up_assurance'] = [];
$noStepUp = $coordinator->advance($incident, 'closed', 'closure', 'incident:cycle161-close', ['approval:human-one', 'approval:human-two']);
c161(is_wp_error($noStepUp) && $noStepUp->get_error_code() === 'spcrc_critical_incident_step_up_required', 'Critical incident closure must require fresh step-up after dual approval.');
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$closed = $coordinator->advance($incident, 'closed', 'closure', 'incident:cycle161-close', ['approval:human-one', 'approval:human-two'], 'assertion:cycle161-incident-stepup');
c161($closed === true, 'Critical incident closure must succeed only with authority, dual approvals and fresh step-up assurance.');

echo "PASS: cycle161 release exception and critical-incident closure governance defects fixed and retested\n";
