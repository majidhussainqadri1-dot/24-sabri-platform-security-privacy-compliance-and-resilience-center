<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\SystemCheck;

function v123CapacityMarkerAssert(bool $ok, string $message): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$check = new SystemCheck(new ModuleRegistry());
$baseline = array_column($check->run(), null, 'key');
v123CapacityMarkerAssert(
    ($baseline['audit_gaps']['status'] ?? '') === 'pass',
    'Empty canonical audit-gap stores have no invented capacity-marker incident.'
);

$GLOBALS['wp_options']['spcrc_audit_gap_capacity_marker'] = [
    'option' => 'spcrc_risk_audit_gap',
    'entity_type' => 'risk',
    'reason' => 'unresolved_capacity_overflow',
    'unresolved_count' => 100,
    'recorded_at' => gmdate('c'),
];
$markerOnly = array_column($check->run(), null, 'key');
v123CapacityMarkerAssert(
    ($markerOnly['audit_gaps']['status'] ?? '') === 'critical',
    'Unreconciled capacity-failure evidence must not yield a false-green audit posture.'
);
v123CapacityMarkerAssert(
    str_contains((string) ($markerOnly['audit_gaps']['detail'] ?? ''), 'capacity'),
    'Audit posture must identify the category without disclosing private gap contents.'
);

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_release_gates' => true,
    'spcrc_approve_governance_decision' => true,
];
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$registry = new GovernedArtifactRegistry(new AuditLogger());
$manager = new ReleaseGateManager($registry);
$manager->seed();
$phase = ReleaseGateManager::phases()[0];
$context = [
    'step_up_reference' => 'assertion:v123-capacity-stepup',
    'approval_refs' => ['approval:v123-capacity-one', 'approval:v123-capacity-two'],
];
$blocked = $manager->decide(
    $phase, 'passed', 1, 'evidence:v123-capacity-still-unresolved',
    ['Capacity marker cannot be silently disregarded'], $context
);
v123CapacityMarkerAssert(
    is_wp_error($blocked) && $blocked->get_error_code() === 'spcrc_release_gate_audit_gaps_open',
    'Positive release decision must block while capacity-evidence failure remains.'
);
v123CapacityMarkerAssert(
    ($registry->get('release-gate', $phase)['status'] ?? '') === 'pending',
    'Blocked release must not mutate the original pending gate.'
);

// Simulation of independent authorized recovery: deleting the marker in the
// test harness is not a production reconciliation operation.
unset($GLOBALS['wp_options']['spcrc_audit_gap_capacity_marker']);
$clean = array_column($check->run(), null, 'key');
v123CapacityMarkerAssert(
    ($clean['audit_gaps']['status'] ?? '') === 'pass',
    'An empty legitimate store without marker remains free of invented gaps.'
);

echo "PASS: V12.3 audit-gap capacity marker blocks false-green checks and release progression\n";
