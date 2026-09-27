<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Integration\ConditionalIntegrationCatalog;
use Sabri\Platform\Security\Policy\ContinuousValueAssurance;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;

$count = 0;
$assert = static function (bool $condition, string $message) use (&$count): void {
    ++$count;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
};

$assert(RequirementCatalog::count() === 100 && RequirementCatalog::repositoryCodingComplete(), 'F24-R001..R100 must remain repository complete.');
$assert(ChatDirectiveCatalog::count() === 18 && ChatDirectiveCatalog::repositoryCodingComplete(), 'Recovered CHAT directives must remain 18/18 complete.');
$assert(ContinuousValueRequirementCatalog::count() === 25 && ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value + F24-CEN-01 must remain 25/25 complete.');
$assert(FutureSecurityCapabilityCatalog::count() === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security Superset must remain 25/25 complete.');
$assert(PlatformIntegrationMatrix::complete() && count(PlatformIntegrationMatrix::all()) === 27, 'Files 00-26 integration matrix must remain contiguous and complete.');

$conditional = ConditionalIntegrationCatalog::all();
$assert(count($conditional) === 3, 'Current conditional integration catalogue must contain CF-04, Traffic Analytics and Disease Intelligence.');
$assert(in_array('key_rotation_recovery', $conditional['cf-04-media']['required_controls'] ?? [], true), 'CF-04 must require key rotation/recovery assurance.');
$assert(in_array('private_clinical_path_exclusion', $conditional['traffic-analytics']['required_controls'] ?? [], true), 'Traffic Analytics must exclude private clinical paths.');
$assert(in_array('low_count_geo_content_suppression', $conditional['traffic-analytics']['required_controls'] ?? [], true), 'Traffic Analytics must suppress low-count geo/content slices.');
$assert(in_array('critical_harm_claim_escalation', $conditional['disease-intelligence']['required_controls'] ?? [], true), 'Disease Intelligence must require critical-harm claim escalation.');

$unsupported = ConditionalIntegrationCatalog::evaluate('traffic-analytics', [
    'controls' => $conditional['traffic-analytics']['required_controls'] ?? [],
    'contract_version' => '9.0.0',
    'evidence_ref' => 'evidence:traffic:unsupported',
    'tested_at' => gmdate('c', time() - 60),
    'native_ownership_preserved' => true,
    'feature_flag_off_by_default' => true,
]);
$assert(($unsupported['activation_allowed'] ?? true) === false, 'Unsupported conditional contract versions must fail closed.');

$now = strtotime('2026-09-27T12:00:00Z');
$stale = ContinuousValueAssurance::evaluate('CV-274', [
    'controls' => ['availability_slo','latency_slo','freshness_slo','delivery_slo','recovery_slo','error_budget','public_status_evidence'],
    'evidence_ref' => 'evidence:cv274:stale',
    'reviewed_at' => '2026-01-01T00:00:00Z',
], $now);
$assert(($stale['state'] ?? '') === 'blocked' && ($stale['evidence_fresh'] ?? true) === false, 'Stale Continuous Value evidence must fail closed.');

$matrixSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Registry/PlatformIntegrationMatrix.php');
foreach (['provider-secret','abuse','sensitive-preview','critical-alert/incident containment','provider-retry'] as $needle) {
    $assert(str_contains($matrixSource, $needle), 'File 19 assurance matrix missing: ' . $needle);
}

$pluginSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Plugin.php');
$assert(str_contains($pluginSource, "sun_file24_notification_containment_active"), 'File 19 containment bridge must remain registered.');
$assert(str_contains($pluginSource, "'incident-containment'") && str_contains($pluginSource, "'platform-read-only'"), 'Platform-wide containment states must remain canonical.');

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$assert(str_contains($ci, "php: ['8.0', '8.3']"), 'CI must run PHP 8.0 and 8.3.');
$assert(str_contains($ci, "file24-source-snapshot-cycle280.zip"), 'CI source snapshot must reflect Cycle 280.');
$assert(! str_contains($ci, "file24-source-snapshot-cycle279.zip"), 'CI must not regress to stale Cycle 279 snapshot naming.');
$assert(str_contains($ci, 'find tests -maxdepth 1') && str_contains($ci, "! -name 'bootstrap.php'"), 'CI must enumerate every independent top-level PHP regression, including this review test.');

$sourceManifest = json_decode((string) file_get_contents(__DIR__ . '/../docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
$assert(($sourceManifest['latest_repository_correction_cycle'] ?? null) === 280, 'Source manifest must retain Cycle 280 as latest numbered repository correction.');
$assert(($sourceManifest['integration_files']['count'] ?? null) === 27, 'Source manifest must record Files 00-26.');

echo "PASS: {$count} assertions — twenty-round cross-plan closure regression\n";
