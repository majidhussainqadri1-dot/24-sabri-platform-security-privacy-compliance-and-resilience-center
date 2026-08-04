<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Storage\Schema;

$count = 0;
function c100(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

$root = dirname(__DIR__);
$plugin = (string) file_get_contents($root . '/plugin/sabri-security-center/sabri-security-center.php');
$readme = (string) file_get_contents($root . '/plugin/sabri-security-center/readme.txt');
$sbom = json_decode((string) file_get_contents($root . '/plugin/sabri-security-center/SBOM.spdx.json'), true, 512, JSON_THROW_ON_ERROR);
$schema = json_decode((string) file_get_contents($root . '/docs/SCHEMA-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);

c100(str_contains($plugin, 'Version:     0.99.0') && str_contains($plugin, "define('SPCRC_VERSION', '0.99.0')"), 'Plugin identity must be 0.99.0.');
c100(str_contains($readme, 'Stable tag: 0.99.0'), 'WordPress stable tag must be 0.99.0.');
c100(($sbom['packages'][0]['versionInfo'] ?? '') === '0.99.0', 'SBOM version must match runtime.');
c100(Schema::VERSION === '0.25.5' && ($schema['schema_version'] ?? '') === '0.25.5', 'Schema manifest must match code.');
c100(RequirementCatalog::count() === 100 && RequirementCatalog::repositoryCodingComplete(), 'F24-R001–F24-R100 must be repository complete.');
c100(count(PlatformIntegrationMatrix::all()) === 26, 'File 00–25 matrix must be complete.');
c100(count(GovernedArtifactRegistry::types()) === 28, 'Logical governed domains must be complete.');
c100(count(BoundaryPolicyCatalog::all()) === 6, 'High-risk boundary policy catalogue must be complete.');
c100(count(ReleaseGateManager::phases()) === 12, 'Phases 24A–24L must be implemented.');
c100(count(Capabilities::all()) >= 27, 'Least-privilege operational capabilities must be declared.');

$status = ReleaseStatus::summary();
c100(($status['version'] ?? '') === '0.99.0' && ! empty($status['repository_coding_complete']), 'Release status must identify repository code completion.');
c100(empty($status['production_ready']), 'Repository coding must not falsely claim production readiness.');
c100(in_array('staging_accepted', $status['pending_external_gates'] ?? [], true), 'Staging acceptance must remain a later gate.');
c100(in_array('live_deployed', $status['pending_external_gates'] ?? [], true), 'Live deployment must remain a later gate.');
c100(in_array('operational', $status['pending_external_gates'] ?? [], true), 'Operational acceptance must remain a later gate.');

$requiredDocs = [
    'CODE-COMPLETE-SUMMARY-0.99.0.md', 'RELEASE-RECEIPT-0.99.0.md', 'KNOWN-LIMITATIONS-0.99.0.md',
    'REQUIREMENTS-TRACEABILITY-0.99.0.md', 'LOGICAL-DATA-MODEL-0.99.0.md', 'SCHEMA-MANIFEST-0.99.0.json',
    'THREAT-MODEL-0.99.0.md', 'FILES-00-25-INTEGRATION-MATRIX-0.99.0.md', 'IMPLEMENTATION-PHASES-0.99.0.md',
    'MIGRATION-ROLLBACK-0.99.0.md', 'QA-PLAN-0.99.0.md', 'CHANGE-CONTROL-0.99.0.md',
    'REVIEW-AND-CORRECTION-0.99.0-ROUND-1.md', 'REVIEW-AND-CORRECTION-0.99.0-ROUND-2.md',
    'REVIEW-AND-CORRECTION-0.99.0-ROUND-3.md', 'REVIEW-AND-CORRECTION-0.99.0-ROUND-4.md',
    'SECURITY-ARCHITECTURE-0.99.0.md', 'DATA-FLOW-OWNERSHIP-0.99.0.md', 'CONTROL-CATALOG-0.99.0.md',
    'MODULE-SECURITY-SDK-0.99.0.md', 'API-EVENT-CONTRACTS-0.99.0.md', 'COMPLIANCE-APPLICABILITY-0.99.0.md',
    'INCIDENT-RESPONSE-PLAN-0.99.0.md', 'DISASTER-RECOVERY-PLAN-0.99.0.md', 'BACKUP-RESTORE-GUIDE-0.99.0.md',
    'KEY-GOVERNANCE-GUIDE-0.99.0.md', 'SOURCE-MANIFEST-0.99.0.json',
];
foreach ($requiredDocs as $doc) c100(is_file($root . '/docs/' . $doc), 'Required repository document missing: ' . $doc);
$manuals = ['ADMINISTRATOR-MANUAL.md','PRIVACY-OFFICER-MANUAL.md','INCIDENT-COMMANDER-MANUAL.md','BACKUP-OPERATOR-MANUAL.md','DEVELOPER-SECURITY-GUIDE.md','TRUST-CENTER-GUIDANCE.md','SCHEMA-MANIFEST.json','SOURCE-MANIFEST.json','SECURITY-ARCHITECTURE.md','DATA-FLOW-OWNERSHIP.md','CONTROL-CATALOG.md','MODULE-SECURITY-SDK.md','API-EVENT-CONTRACTS.md','COMPLIANCE-APPLICABILITY.md','INCIDENT-RESPONSE-PLAN.md','DISASTER-RECOVERY-PLAN.md','BACKUP-RESTORE-GUIDE.md','KEY-GOVERNANCE-GUIDE.md'];
foreach ($manuals as $manual) c100(is_file($root . '/plugin/sabri-security-center/docs/' . $manual), 'Required packaged manual missing: ' . $manual);

$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
c100(str_contains($ci, 'cycle100-repository-code-complete-closure.php') || str_contains($ci, 'find tests -maxdepth 1'), 'Permanent CI must run repository closure test.');
c100(is_file($root . '/CHECKSUMS.sha256'), 'Source checksum ledger must exist.');
c100(is_executable($root . '/tools/build-release.sh'), 'Deterministic build tool must remain executable.');

echo "PASS: $count Cycle 100 repository code-complete closure assertions\n";
