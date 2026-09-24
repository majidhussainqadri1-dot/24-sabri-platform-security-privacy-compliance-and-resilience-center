<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Integration\ConditionalIntegrationCatalog;
use Sabri\Platform\Security\Integration\File02Adapter;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Release\ReleaseStatus;

$count = 0;
function c278(bool $condition, string $message): void
{
    global $count;
    ++$count;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$registry = new ModuleRegistry();
$legacy = [
    'module_key' => 'legacy-contract',
    'name' => 'Legacy Contract',
    'version' => '1.0.0',
    'owner' => 'Legacy owner',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => [],
    'posture' => 'operational',
];
$legacyResult = $registry->validate($legacy);
c278(is_array($legacyResult), 'Legacy-shaped manifest remains parseable for compatibility.');
c278(($legacyResult['contract_complete'] ?? true) === false, 'Incomplete manifest must be explicitly marked incomplete.');
c278(($legacyResult['posture'] ?? '') === 'unassessed', 'Incomplete manifest must never retain an assessed/operational posture.');
c278(in_array('contract_version', $legacyResult['contract_gaps'] ?? [], true), 'Missing explicit contract version must be reported.');
c278(in_array('verification_level', $legacyResult['contract_gaps'] ?? [], true), 'Missing verification target must be reported.');
c278(in_array('emergency_callbacks', $legacyResult['contract_gaps'] ?? [], true), 'Missing emergency callbacks inventory must be reported.');

$complete = array_merge($legacy, [
    'tables' => ['logical-table-domain'],
    'files' => ['logical-file-domain'],
    'capabilities' => [],
    'external_vendors' => [],
    'secret_classes' => ['secret-metadata-only'],
    'privacy_operations' => [],
    'exporters' => [],
    'erasers' => [],
    'emergency_callbacks' => ['safe-shutdown'],
    'last_security_test' => '',
    'verification_level' => 'asvs-l2',
    'contract_version' => '1.2.0',
    'canonical_data_owner' => 'Legacy owner',
    'canonical_action_owner' => 'Legacy owner',
    'evidence_source' => 'module:legacy-contract',
    'degraded_behavior' => 'Writes fail closed.',
    'release_gate' => 'Contract tests and staging acceptance.',
    'posture' => 'foundation',
]);
$completeResult = $registry->validate($complete);
c278(is_array($completeResult) && ($completeResult['contract_complete'] ?? false) === true, 'Complete security manifest must validate as complete.');
c278(($completeResult['contract_gaps'] ?? ['x']) === [], 'Complete manifest must have zero contract gaps.');

if (! defined('SAUTH_VERSION')) {
    define('SAUTH_VERSION', '1.0.0');
}
$file02 = new File02Adapter();
$file02Manifest = $file02->manifest([]);
c278(isset($file02Manifest[0]) && is_array($file02Manifest[0]), 'File 02 adapter must publish a manifest.');
$file02Validated = $registry->validate($file02Manifest[0]);
c278(is_array($file02Validated) && ($file02Validated['contract_complete'] ?? false) === true, 'File 02 adapter manifest must satisfy the current complete contract.');
c278(($file02Validated['posture'] ?? '') !== 'unassessed', 'Available File 02 must not be downgraded by schema mismatch.');

c278(PlatformIntegrationMatrix::complete(), 'Files 00–26 fail-safe integration matrix must be structurally complete.');
foreach (PlatformIntegrationMatrix::all() as $file => $row) {
    foreach (['failure_mode','default_behavior','user_message','alert_owner','recovery_owner','exit_criteria','degraded_behavior'] as $field) {
        c278(trim((string) ($row[$field] ?? '')) !== '', 'File ' . $file . ' missing fail-safe field ' . $field);
    }
}

c278(ConditionalIntegrationCatalog::count() === 3, 'Exactly three current conditional cross-file assurance contracts must be encoded.');
c278(ConditionalIntegrationCatalog::repositoryCodingComplete(), 'Conditional cross-file catalog must be repository complete.');

$fixtures = [
    'cf-04-media' => [
        'native_scan_preserved', 'native_authorization_preserved', 'native_encryption_preserved',
        'upload_quarantine', 'provider_region_review', 'provider_security_review', 'provider_exit_plan',
        'credential_plan', 'rights_aware_delivery', 'short_lived_delivery', 'revocation',
        'deletion_propagation', 'audit',
    ],
    'traffic-analytics' => [
        'declared_measurement_purpose', 'data_minimization', 'optional_analytics_consent',
        'consent_withdrawal', 'no_covert_tracking', 'no_data_sale', 'no_commercial_profiling',
        'url_query_sanitization', 'no_auth_tokens_in_logs', 'minor_health_interest_profiling_forbidden',
        'export_authorization', 'sensitive_admin_step_up', 'retention_rule', 'incident_route',
    ],
    'disease-intelligence' => [
        'native_disease_truth_preserved', 'source_provenance', 'medical_review',
        'no_autonomous_diagnosis', 'no_autonomous_prescription', 'privacy_minimization',
        'ranking_policy_versioned', 'ranking_explainable', 'ranking_rollback',
        'correction_retraction_propagation', 'bot_interest_anomaly_monitor',
        'cache_index_reconciliation', 'backup_restore_rebuild_evidence', 'incident_route',
    ],
];
$now = strtotime('2026-09-24T08:00:00Z');
foreach ($fixtures as $key => $controls) {
    $result = ConditionalIntegrationCatalog::evaluate($key, [
        'controls' => $controls,
        'contract_version' => '1.0.0',
        'evidence_ref' => 'evidence:' . $key,
        'tested_at' => '2026-09-24T07:30:00Z',
        'native_ownership_preserved' => true,
        'feature_flag_off_by_default' => true,
    ], $now);
    c278(($result['state'] ?? '') === 'verified' && ($result['activation_allowed'] ?? false), $key . ' complete evidence must verify.');

    $blocked = ConditionalIntegrationCatalog::evaluate($key, [
        'controls' => $controls,
        'contract_version' => '1.0.0',
        'evidence_ref' => 'evidence:' . $key,
        'tested_at' => '2026-09-24T07:30:00Z',
        'native_ownership_preserved' => false,
        'feature_flag_off_by_default' => true,
    ], $now);
    c278(($blocked['activation_allowed'] ?? true) === false, $key . ' must fail closed when native ownership is not preserved.');
}

c278((ConditionalIntegrationCatalog::evaluate('unknown', [], $now)['activation_allowed'] ?? true) === false, 'Unknown conditional integration must fail closed.');

$sourceManifest = json_decode((string) file_get_contents(dirname(__DIR__) . '/docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
c278(($sourceManifest['integration_files']['last'] ?? null) === 26, 'Source manifest must end at File 26.');
c278(($sourceManifest['integration_files']['count'] ?? null) === 27, 'Source manifest must record 27 permanent files.');
c278(count($sourceManifest['conditional_integrations'] ?? []) === 3, 'Source manifest must record the three conditional integrations.');

$review = (string) file_get_contents(dirname(__DIR__) . '/docs/EIGHTY-ROUND-REVIEW-AND-CORRECTION-CYCLES-198-277.md');
c278(str_contains($review, 'Defect-bearing requested rounds | **9**'), 'Eighty-round register must use corrected nine-defect truth.');
c278(str_contains($review, 'Clean requested rounds after those fixes | **71**'), 'Eighty-round register must use corrected seventy-one clean rounds.');

$ci = (string) file_get_contents(dirname(__DIR__) . '/.github/workflows/ci.yml');
c278(str_contains($ci, 'cycle278-cross-file-completion.php'), 'CI must explicitly retain the Cycle 278 cross-file completion regression.');
c278(str_contains($ci, 'ConditionalIntegrationCatalog::repositoryCodingComplete()'), 'CI must gate conditional integration completion.');
c278(str_contains($ci, 'file24-source-snapshot-cycle278.zip'), 'CI snapshot path naming must reflect the current correction cycle.');
c278(str_contains($ci, 'file-24-sanitized-source-snapshot-cycle278'), 'CI uploaded artifact name must reflect the current correction cycle.');

c278(ReleaseStatus::repositoryCodingComplete(), 'Repository coding status must include the corrected manifest, matrix and conditional-integration gates.');
c278(! ReleaseStatus::productionReady(), 'Repository correction must not assert staging/live/operational acceptance.');

echo "PASS: {$count} Cycle 278 cross-file completion assertions\n";
