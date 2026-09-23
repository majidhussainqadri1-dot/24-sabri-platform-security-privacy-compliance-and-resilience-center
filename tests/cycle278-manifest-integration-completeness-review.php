<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Integration\File02Adapter;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;

function c278(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$registry = new ModuleRegistry();
$legacy = $registry->validate([
    'module_key' => 'legacy-module',
    'name' => 'Legacy Module',
    'version' => '1.0.0',
    'owner' => 'Legacy Owner',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => [],
]);
c278(is_array($legacy), 'Legacy manifests must remain parseable for backward compatibility.');
c278(empty($legacy['manifest_complete']), 'Legacy manifests missing the full contract must not be treated as complete.');
c278(($legacy['posture'] ?? '') === 'unassessed', 'Incomplete manifests must be forced to unassessed posture.');
c278(($legacy['contract_version'] ?? 'x') === '', 'Missing contract version must not be fabricated as 1.0.0.');

$full = $registry->validate([
    'module_key' => 'complete-module',
    'name' => 'Complete Module',
    'version' => '1.0.0',
    'owner' => 'File 99',
    'posture' => 'foundation',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => [],
    'capabilities' => [],
    'external_vendors' => [],
    'privacy_operations' => [],
    'tables' => [],
    'files' => [],
    'secrets' => [],
    'exporters' => [],
    'erasers' => [],
    'emergency_callbacks' => [],
    'asvs_level_target' => 'ASVS-L2',
    'last_security_test' => '',
    'contract_version' => '1.0.0',
    'canonical_data_owner' => 'File 99',
    'canonical_action_owner' => 'File 99',
    'evidence_source' => 'module:complete-module',
    'degraded_behavior' => 'Unsafe writes fail closed while native safe reads continue.',
    'release_gate' => 'Staging contract and regression acceptance',
]);
c278(is_array($full) && ! empty($full['manifest_complete']), 'A full manifest must satisfy the canonical manifest contract.');
c278(($full['posture'] ?? '') === 'foundation', 'A complete manifest may retain its declared valid posture.');

if (! defined('SAUTH_VERSION')) {
    define('SAUTH_VERSION', '1.0.0');
}
$file02 = new File02Adapter();
$manifests = $file02->manifest([]);
c278(count($manifests) === 1, 'Available File 02 must publish one canonical manifest.');
$file02Validated = $registry->validate($manifests[0]);
c278(is_array($file02Validated) && ! empty($file02Validated['manifest_complete']), 'File 02 manifest must match the current ModuleRegistry schema.');
c278(($file02Validated['posture'] ?? '') === 'foundation', 'File 02 posture must remain valid after normalization.');
c278($file02->contractState('unassessed') === 'compatible', 'File 02 contract cannot report compatible unless its manifest validates as complete.');

c278(PlatformIntegrationMatrix::complete(), 'Files 00-26 integration matrix and fail-safe contract must be complete.');
foreach (PlatformIntegrationMatrix::all() as $file => $definition) {
    foreach (['contract_version','failure_mode','user_message','alert_owner','recovery_owner','exit_criteria'] as $field) {
        c278(trim((string) ($definition[$field] ?? '')) !== '', 'File ' . $file . ' missing fail-safe field ' . $field . '.');
    }
}

echo "PASS: Cycle 278 manifest and integration completeness corrections passed\n";
