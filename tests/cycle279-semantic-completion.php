<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Integration\ContractCompatibilityPolicy;
use Sabri\Platform\Security\Integration\File00Adapter;
use Sabri\Platform\Security\Integration\File02Adapter;
use Sabri\Platform\Security\Integration\File20Adapter;
use Sabri\Platform\Security\Monitoring\PerformanceObjectiveContract;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\LaunchBlockerContract;
use Sabri\Platform\Security\Release\ReleaseStatus;

$count = 0;
function c279(bool $condition, string $message): void
{
    global $count;
    ++$count;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$registry = new ModuleRegistry();
$base = [
    'module_key' => 'cycle279',
    'name' => 'Cycle 279 semantic contract',
    'version' => '1.0.0',
    'owner' => 'File 279 fixture',
    'posture' => 'foundation',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => [],
    'tables' => ['logical-domain'],
    'files' => ['logical-file-domain'],
    'capabilities' => [],
    'external_vendors' => [],
    'secret_classes' => [],
    'privacy_operations' => [],
    'exporters' => [],
    'erasers' => [],
    'emergency_callbacks' => ['safe-shutdown'],
    'last_security_test' => '',
    'verification_level' => 'asvs-l2',
    'contract_version' => ContractCompatibilityPolicy::MANIFEST_CURRENT,
    'canonical_data_owner' => 'File 279 fixture',
    'canonical_action_owner' => 'File 279 fixture',
    'evidence_source' => 'evidence:cycle279',
    'degraded_behavior' => 'Writes fail closed.',
    'release_gate' => 'Exact-head contract tests and staging acceptance.',
];

$untested = $registry->validate($base);
c279(is_array($untested) && empty($untested['contract_complete']), 'A manifest without last-security-test evidence must not be complete.');
c279(in_array('last_security_test', $untested['contract_gaps'] ?? [], true), 'Missing last-security-test evidence must be reported.');

$tested = $registry->validate(array_merge($base, ['last_security_test' => gmdate('c', time() - 60)]));
c279(is_array($tested) && ! empty($tested['contract_complete']), 'A current-version manifest with real test timestamp must satisfy semantic completeness.');
c279(($tested['contract_version_state'] ?? '') === 'compatible', 'Current manifest contract version must be explicitly compatible.');

$deprecated = $registry->validate(array_merge($base, [
    'last_security_test' => gmdate('c', time() - 60),
    'contract_version' => '1.1.9',
]));
c279(is_array($deprecated) && empty($deprecated['contract_complete']), 'Deprecated manifest contract versions must not be complete.');
c279(in_array('contract_version_compatibility', $deprecated['contract_gaps'] ?? [], true), 'Deprecated contract version must expose a compatibility gap.');

c279(ContractCompatibilityPolicy::repositoryCodingComplete(), 'Compatibility/deprecation policy must be executable.');
c279(ContractCompatibilityPolicy::evaluate('1.1.9', '1.2.0', '2.0.0') === 'deprecated', 'Below-minimum versions must be deprecated.');
c279(ContractCompatibilityPolicy::evaluate('2.0.0', '1.2.0', '2.0.0') === 'blocked', 'Unreviewed next-major contracts must fail closed.');

if (! defined('SMC_VERSION')) define('SMC_VERSION', '1.2.44');
if (! defined('SMC_CONTRACT_VERSION')) define('SMC_CONTRACT_VERSION', '1.2.3');
if (! function_exists('smc_user_status')) { function smc_user_status(int $userId): string { return $userId > 0 ? 'active' : 'unknown'; } }
if (! function_exists('smc_is_founder')) { function smc_is_founder(int $userId): bool { return $userId === 1; } }
$file00 = new File00Adapter();
c279($file00->contractState('unassessed') === 'compatible', 'File 00 native contract must resolve through its versioned compatibility bridge.');

if (! defined('SAUTH_VERSION')) define('SAUTH_VERSION', '1.3.4');
if (! defined('SAUTH_ACCOUNT_CONTRACT_VERSION')) define('SAUTH_ACCOUNT_CONTRACT_VERSION', '1.1.0');
$file02 = new File02Adapter();
c279($file02->contractState('unassessed') === 'compatible', 'File 02 native contract must resolve through its versioned compatibility bridge.');
c279(method_exists(File20Adapter::class, 'contractState'), 'File 20 must expose an explicit contract-state bridge.');

c279(PerformanceObjectiveContract::repositoryCodingComplete(), 'F24-R092 must define all governed measurable metrics.');
$objectives = [];
$measurements = [];
foreach (PerformanceObjectiveContract::definitions() as $metric => $definition) {
    $objectives[$metric] = [
        'unit' => $definition['unit'],
        'direction' => $definition['direction'],
        'threshold' => $definition['direction'] === 'maximum' ? 100 : 10,
        'environment' => 'staging',
        'effective_version' => '0.99.0',
        'measurement_window_seconds' => 300,
        'evidence_ref' => 'perf:' . $metric,
    ];
    $measurements[$metric] = $definition['direction'] === 'maximum' ? 50 : 20;
}
$performance = PerformanceObjectiveContract::evaluate($objectives, $measurements);
c279(($performance['state'] ?? '') === 'measured' && ! empty($performance['release_ready']), 'Complete in-threshold performance evidence must measure cleanly.');
$measurements['dashboard_p95_latency'] = 150;
$breached = PerformanceObjectiveContract::evaluate($objectives, $measurements);
c279(($breached['state'] ?? '') === 'breached' && in_array('dashboard_p95_latency', $breached['breaches'] ?? [], true), 'Threshold breaches must be machine-detected.');

c279(in_array('launch-blocker', GovernedArtifactRegistry::types(), true), 'Formal launch-blocker registry domain must exist.');
c279(LaunchBlockerContract::repositoryCodingComplete(), 'F24-R096 launch blocker field contract must be complete.');
$failOpen = LaunchBlockerContract::validateArtifact('open', 7, '', [
    'affected_feature' => 'private-attachments',
    'due_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'severity' => 'critical',
    'feature_disabled' => false,
]);
c279(is_wp_error($failOpen) && $failOpen->get_error_code() === 'spcrc_launch_blocker_fail_open', 'Unresolved critical blocker must fail closed.');
$validBlocker = LaunchBlockerContract::validateArtifact('open', 7, '', [
    'affected_feature' => 'private-attachments',
    'due_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'severity' => 'critical',
    'feature_disabled' => true,
]);
c279($validBlocker === true, 'Formal blocker with owner/due/affected-feature/fail-closed state must validate.');

c279((RequirementCatalog::get('F24-R088')['title'] ?? '') === 'Files 00–26 Integration Matrix', 'F24-R088 must use the permanent 00–26 matrix title.');
c279(ModuleRegistry::repositoryContractSchemaComplete(), 'Repository completion must include semantic manifest contract rules.');
c279(ReleaseStatus::repositoryCodingComplete(), 'Repository coding completion must include Cycle 279 semantic closure.');

$root = dirname(__DIR__);
$legacyMatrix = (string) file_get_contents($root . '/docs/FILES-00-25-INTEGRATION-MATRIX-0.99.0.md');
$integrationContracts = (string) file_get_contents($root . '/docs/INTEGRATION-CONTRACTS.md');
$summary = (string) file_get_contents($root . '/docs/CODE-COMPLETE-SUMMARY-0.99.0.md');
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
c279(str_contains($legacyMatrix, 'SUPERSEDED') && str_contains($legacyMatrix, 'FILES-00-26-INTEGRATION-MATRIX-0.99.0.md'), 'Legacy 00–25 document must be explicitly non-governing.');
c279(str_contains($integrationContracts, '0.99.0') && str_contains($integrationContracts, 'last_security_test'), 'Current integration contract documentation must match the strict manifest contract.');
c279(str_contains($summary, 'Cycle 279'), 'Code-complete summary must identify the latest semantic correction cycle.');
c279(str_contains($ci, 'file24-source-snapshot-cycle279.zip') && str_contains($ci, 'cycle279-semantic-completion.php'), 'CI must publish and test the Cycle 279 corrected source.');

echo "PASS: {$count} Cycle 279 semantic completion assertions\n";
