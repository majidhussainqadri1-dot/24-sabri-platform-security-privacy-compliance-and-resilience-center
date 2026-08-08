<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Rest\GovernanceController;
use Sabri\Platform\Security\Storage\AuditLogger;

function c172(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_release_gates' => true,
    'spcrc_view_overview' => true,
    'spcrc_approve_governance_decision' => true,
];
$registry = new GovernedArtifactRegistry(new AuditLogger());
$controller = new GovernanceController($registry);
$request = [
    'artifact_type' => 'release-gate',
    'artifact_key' => '24a-governance-source-freeze',
    'title' => 'Attempted generic bypass',
    'status' => 'passed',
    'classification' => 'C1',
    'expected_version' => 0,
    'evidence_ref' => 'evidence:cycle172',
    'step_up_reference' => 'assertion:cycle172',
];

c172($controller->canSave($request) === false, 'Generic governance REST surface must not mutate release gates that require ReleaseGateManager dual-control sequencing.');
$blocked = $controller->saveArtifact($request);
c172(is_wp_error($blocked) && $blocked->get_error_code() === 'spcrc_governance_write_forbidden', 'Generic REST release-gate mutation must fail closed even for release managers.');

$restSource = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Rest/GovernanceController.php');
$adminSource = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Admin/RegistryAdmin.php');
c172(is_string($restSource) && str_contains($restSource, "SPECIALIZED_WRITE_TYPES = ['release-gate']"), 'REST dedicated-service ownership guard must remain encoded.');
c172(is_string($adminSource) && str_contains($adminSource, "SPECIALIZED_WRITE_TYPES = ['release-gate']") && str_contains($adminSource, 'return false;'), 'wp-admin generic registry fallback must not expose a release-gate write bypass.');

echo "PASS: cycle172 release-gate generic mutation-surface bypass defect fixed and retested\n";
