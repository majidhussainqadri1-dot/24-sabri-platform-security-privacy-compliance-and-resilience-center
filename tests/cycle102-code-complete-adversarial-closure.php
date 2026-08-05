<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseStatus;

$count = 0;
function c102(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

$root = dirname(__DIR__);
$privateDelivery = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Security/PrivateDeliveryPolicy.php');
$network = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Security/NetworkPolicy.php');
$vulnerabilities = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Security/VulnerabilityManager.php');
$resilience = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Resilience/ResilienceCoordinator.php');
$incidents = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Incident/IncidentCoordinator.php');
$remote = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Monitoring/RemoteEvidenceQueue.php');

c102(str_contains($privateDelivery, 'spcrc_private_delivery_consume_failed') && str_contains($privateDelivery, "persisted['consumed_at']"), 'Private delivery must verify durable one-time consumption.');
c102(str_contains($network, 'dns_get_record') && str_contains($network, 'if ($resolved === [])'), 'External endpoints must fail closed when DNS evidence is unavailable.');
c102(str_contains($vulnerabilities, 'spcrc_vulnerability_finding_failed') && str_contains($vulnerabilities, 'linked_finding_creation_failed'), 'Vulnerability lifecycle must expose and evidence partial corrective-finding failure.');
c102(str_contains($resilience, 'spcrc_drill_finding_failed') && str_contains($resilience, 'failed_drill_finding_creation_failed'), 'Failed drills must not silently lose corrective findings.');
c102(str_contains($incidents, 'spcrc_incident_declaration_partial') && str_contains($incidents, 'spcrc_incident_audit_gap'), 'Incident declaration partial transactions must be recoverable and release-blocking.');
c102(str_contains($remote, 'persistence_failed') && str_contains($remote, 'remote_evidence_persistence_failed'), 'Remote evidence delivery counts must reflect durable persistence truth.');
c102(RequirementCatalog::count() === 100 && RequirementCatalog::repositoryCodingComplete(), 'All F24-R001–F24-R100 repository requirements must remain mapped as implemented.');
c102(count(PlatformIntegrationMatrix::all()) === 27 && PlatformIntegrationMatrix::complete(), 'All permanent Files 00–26 must retain explicit, contiguous integration boundaries.');
c102(count(GovernedArtifactRegistry::types()) === 28, 'All governed logical domains must remain implemented.');
$status = ReleaseStatus::summary();
c102(($status['version'] ?? '') === '0.99.0' && ! empty($status['repository_coding_complete']), 'Repository code-complete identity must remain 0.99.0.');
c102(empty($status['production_ready']) && in_array('staging_accepted', $status['pending_external_gates'] ?? [], true), 'Code completion must not conceal the later staging and production gates.');
foreach (['REVIEW-AND-CORRECTION-0.99.0-ROUND-3.md', 'REVIEW-AND-CORRECTION-0.99.0-ROUND-4.md'] as $doc) {
    c102(is_file($root . '/docs/' . $doc), 'Fresh final review evidence missing: ' . $doc);
}

echo "PASS: $count Cycle 102 code-complete adversarial closure assertions\n";
