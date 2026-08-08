<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;

function c171(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_release_gates' => true,
    'spcrc_approve_governance_decision' => true,
];
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
add_filter('spcrc/verify_founder_risk_acceptance', '__return_true', 10, 4);

$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();
$phase = ReleaseGateManager::phases()[0];
$riskRef = 'risk-acceptance:cycle171-founder';
$result = $gates->decide($phase, 'waived', 1, 'evidence:cycle171-waiver', ['Founder-governed temporary exception'], [
    'step_up_reference' => 'assertion:cycle171-stepup',
    'approval_refs' => ['approval:cycle171-one', 'approval:cycle171-two'],
    'risk_acceptance_reference' => $riskRef,
]);
c171(is_string($result), 'Governed waiver must succeed with dual control, step-up and verified Founder risk acceptance.');
$record = $registry->get('release-gate', $phase);
c171(is_array($record), 'Waived release gate must remain readable.');
$payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
c171(($payload['risk_acceptance_reference_hash'] ?? '') === hash('sha256', $riskRef), 'Verified waiver risk acceptance must be durably linked by a privacy-safe hash.');
c171(! str_contains(json_encode($payload), $riskRef), 'Raw risk-acceptance reference must not be stored in governed release metadata.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Release/ReleaseGateManager.php');
c171(is_string($source) && str_contains($source, 'risk_acceptance_reference_hash'), 'Release waiver evidence-chain field must remain in source.');

echo "PASS: cycle171 release-waiver risk-acceptance evidence-chain defect fixed and retested\n";
