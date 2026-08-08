<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;

function c196(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c196(RequirementCatalog::repositoryCodingComplete(), 'File 24 stable requirement catalogue must remain repository complete.');
c196(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value catalogue must remain repository complete.');
c196(FutureSecurityCapabilityCatalog::repositoryCodingComplete() && count(FutureSecurityCapabilityCatalog::all()) === 25, 'Future Security catalogue must remain 25/25 repository complete.');
c196(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance IDs must retain exact catalogue parity.');
c196(PlatformIntegrationMatrix::complete(), 'Files 00-26 integration assurance matrix must remain complete.');

$root = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
$rate = (string) file_get_contents($root . 'Security/RateLimiter.php');
$privacy = (string) file_get_contents($root . 'Privacy/PrivacyVerificationStore.php');
$module = (string) file_get_contents($root . 'Registry/ModuleRegistry.php');
$artifact = (string) file_get_contents($root . 'Registry/GovernedArtifactRegistry.php');
$governance = (string) file_get_contents($root . 'Storage/GovernanceRepository.php');
$assurance = (string) file_get_contents($root . 'Storage/AssuranceRepository.php');
c196(str_contains($rate, 'spcrc_rate_limit_state_invalid') && str_contains($rate, 'Sanitizer::strictInteger'), 'Rate-limit persisted-state hardening must remain present.');
c196(str_contains($privacy, "'email-confirmed' => self::DAY_SECONDS") && ! str_contains($privacy, "'verified-email-link' => self::DAY_SECONDS"), 'Privacy freshness mapping must use current verification method names.');
c196(str_contains($module, 'spcrc_manifest_route_limit') && str_contains($module, 'spcrc_manifest_list_limit'), 'Manifest completeness gates must remain fail-closed.');
c196(str_contains($artifact, 'spcrc_artifact_payload_list_exceeded') && str_contains($artifact, "'version' => Sanitizer::strictInteger"), 'Governed artifact payload/version integrity gates must remain present.');
c196(str_contains($governance, 'spcrc_governance_expected_lock_version_invalid'), 'Governance optimistic lock parsing must remain strict.');
c196(str_contains($assurance, 'spcrc_assurance_next_review_expired') && str_contains($assurance, 'spcrc_assurance_data_classes_invalid'), 'Assurance freshness and completeness gates must remain present.');

echo "PASS: cycle196 first fresh post-fix whole-system review found no new repository-correctable defect\n";
