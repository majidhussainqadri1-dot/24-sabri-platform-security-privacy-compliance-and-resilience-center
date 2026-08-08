<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;

function c164(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c164(count(RequirementCatalog::all()) === 100 && RequirementCatalog::repositoryCodingComplete(), 'Stable F24-R001..R100 catalogue must remain repository complete.');
c164(count(FutureSecurityCapabilityCatalog::all()) === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security Superset must remain exact 25/25 and repository complete.');
c164(count(PlatformIntegrationMatrix::all()) === 27 && PlatformIntegrationMatrix::complete(), 'Files 00-26 integration matrix must remain complete without duplicate File 24 ownership.');
c164(count(ReleaseGateManager::phases()) === 12, 'Release phase model must remain 24A-24L.');

$contracts = [
    'Security/EndpointGuard.php' => ['claimExpiringOption', 'spcrc_webhook_replay_detected'],
    'Security/RateLimiter.php' => ['AtomicOptionLock::acquire', 'spcrc_rate_lock_'],
    'Security/PrivateDeliveryPolicy.php' => ['spcrc_private_delivery_consume_lock_', 'spcrc_private_delivery_reauthorization_failed'],
    'Privacy/DeletionReplayManager.php' => ['dispatching', 'lease_lost_during_dispatch', 'spcrc_deletion_replay_audit_gap'],
    'Monitoring/RemoteEvidenceQueue.php' => ['delivering', 'lease_lost_during_delivery', 'spcrc_remote_evidence_audit_gap'],
    'Release/ReleaseGateManager.php' => ['spcrc_release_gate_known_defects_blocked', 'spcrc_release_gate_risk_acceptance_required'],
    'Incident/IncidentCoordinator.php' => ['spcrc_critical_incident_step_up_required', 'spcrc_critical_incident_dual_approval_required'],
    'Resilience/ResilienceCoordinator.php' => ['spcrc_resilience_expected_version_invalid', '], $expectedVersion);'],
    'Policy/GovernancePolicyService.php' => ['spcrc_policy_expected_version_invalid', '], $expectedVersion);'],
    'Privacy/DataGovernanceRegistry.php' => ['spcrc_data_governance_expected_version_invalid', 'Sanitizer::strictInteger'],
    'Trust/TrustCenterService.php' => ['spcrc_trust_claim_expected_version_invalid', 'Sanitizer::strictInteger'],
];
foreach ($contracts as $relative => $needles) {
    $source = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/' . $relative);
    foreach ($needles as $needle) {
        c164(str_contains($source, $needle), $relative . ' must retain corrected contract marker ' . $needle . '.');
    }
}

$sourceRoot = __DIR__ . '/../plugin/sabri-security-center/src';
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceRoot, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if (! $file->isFile() || $file->getExtension() !== 'php') { continue; }
    $source = (string) file_get_contents($file->getPathname());
    c164(preg_match('/absint\([^\n;]*expected_version/', $source) !== 1, 'No mutation boundary may coerce expected_version with absint: ' . $file->getFilename());
}

echo "PASS: cycle164 fresh whole-system adversarial review found no new repository-correctable defect\n";
