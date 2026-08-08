<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c177(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c177(RequirementCatalog::count() === 100 && RequirementCatalog::repositoryCodingComplete(), 'All F24-R001–R100 repository requirements must remain closed.');
c177(ChatDirectiveCatalog::count() === 18 && ChatDirectiveCatalog::repositoryCodingComplete(), 'All recovered chat directives must remain repository-complete.');
c177(ContinuousValueRequirementCatalog::count() === 25 && ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Current-plan Continuous Value requirements must remain repository-complete.');
c177(count(FutureSecurityCapabilityCatalog::all()) === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security Superset must remain complete.');
c177(count(PlatformIntegrationMatrix::all()) === 27 && PlatformIntegrationMatrix::complete(), 'Files 00–26 integration matrix must remain complete.');
c177(ReleaseStatus::repositoryCodingComplete(), 'Release status must still report repository coding complete without overstating staging/live.');

$checks = [
    'Monitoring/RemoteEvidenceQueue.php' => ['IN_FLIGHT_STALE_SECONDS', "['queued', 'retry', 'delivering']"],
    'Privacy/DeletionReplayManager.php' => ['IN_FLIGHT_STALE_SECONDS', "recordStatus === 'blocked-hold'"],
    'Security/EndpointGuard.php' => ['spcrc_endpoint_network_identity_missing', 'spcrc_endpoint_rate_policy_invalid', '$idempotencyScope'],
    'Release/ReleaseGateManager.php' => ['risk_acceptance_reference_hash', 'spcrc_release_gate_known_defects_blocked'],
    'Incident/IncidentCoordinator.php' => ['persistCriticalClosureApproval', 'spcrc_critical_incident_approval_evidence_conflict'],
    'Registry/GovernedArtifactRegistry.php' => ['spcrc_artifact_owner_invalid'],
    'Privacy/DataGovernanceRegistry.php' => ['spcrc_deletion_attempts_invalid', 'spcrc_deletion_retry_time_invalid'],
    'Rest/GovernanceController.php' => ["SPECIALIZED_WRITE_TYPES = ['release-gate']"],
];
foreach ($checks as $relative => $needles) {
    $source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/' . $relative);
    c177(is_string($source), 'Source must be readable: ' . $relative);
    foreach ($needles as $needle) {
        c177(str_contains($source, $needle), 'Current hardening invariant missing from ' . $relative . ': ' . $needle);
    }
}

echo "PASS: cycle177 fresh whole-system review found no new repository-correctable defect\n";
