<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\GovernancePolicyService;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\FindingRepository;

function c162(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$resilience = new ResilienceCoordinator($registry, new AssuranceRepository(new AuditLogger()), new FindingRepository(new AuditLogger()));
$bia1 = $resilience->saveBia([
    'service_key' => 'cycle162-service', 'title' => 'Cycle 162 BIA v1', 'tier' => 'tier-a', 'status' => 'draft',
]);
c162(! is_wp_error($bia1), 'Resilience wrapper must create a new BIA at version one.');
$biaNoVersion = $resilience->saveBia([
    'service_key' => 'cycle162-service', 'title' => 'Cycle 162 BIA invalid update', 'tier' => 'tier-a', 'status' => 'draft',
]);
c162(is_wp_error($biaNoVersion) && $biaNoVersion->get_error_code() === 'spcrc_artifact_expected_version_required', 'Existing BIA update must remain fail-closed when expected_version is absent.');
$bia2 = $resilience->saveBia([
    'service_key' => 'cycle162-service', 'title' => 'Cycle 162 BIA v2', 'tier' => 'tier-a', 'status' => 'draft', 'expected_version' => 1,
]);
c162(! is_wp_error($bia2), 'Resilience wrapper must pass the caller-supplied optimistic version to the governed registry.');
$bia = $registry->get('bia', 'cycle162-service');
c162(is_array($bia) && ($bia['title'] ?? '') === 'Cycle 162 BIA v2' && (int) ($bia['version'] ?? 0) === 2, 'BIA wrapper must support a genuine versioned update instead of being create-only by accident.');
$biaNegative = $resilience->saveBia([
    'service_key' => 'cycle162-service', 'title' => 'Negative version', 'tier' => 'tier-a', 'status' => 'draft', 'expected_version' => -2,
]);
c162(is_wp_error($biaNegative) && $biaNegative->get_error_code() === 'spcrc_resilience_expected_version_invalid', 'Negative optimistic version must be rejected, not coerced.');

$policies = new GovernancePolicyService($registry);
$p1 = $policies->savePolicy([
    'policy_key' => 'cycle162-policy', 'title' => 'Cycle 162 Policy v1', 'hierarchy_level' => 'procedure', 'policy_version' => '1.0', 'status' => 'draft',
]);
c162(! is_wp_error($p1), 'Policy wrapper must create a new policy.');
$p2 = $policies->savePolicy([
    'policy_key' => 'cycle162-policy', 'title' => 'Cycle 162 Policy v2', 'hierarchy_level' => 'procedure', 'policy_version' => '1.1', 'status' => 'draft', 'expected_version' => 1,
]);
c162(! is_wp_error($p2), 'Policy wrapper must pass expected_version for governed updates.');
$policy = $registry->get('policy', 'cycle162-policy');
c162(is_array($policy) && ($policy['title'] ?? '') === 'Cycle 162 Policy v2' && (int) ($policy['version'] ?? 0) === 2, 'Policy service must no longer be accidentally create-only for existing records.');

$resilienceSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Resilience/ResilienceCoordinator.php');
$policySource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Policy/GovernancePolicyService.php');
c162(substr_count($resilienceSource, '], $expectedVersion);') >= 4, 'All four resilience save surfaces must preserve optimistic concurrency.');
c162(substr_count($policySource, '], $expectedVersion);') >= 2, 'Policy and exception save surfaces must preserve optimistic concurrency.');

echo "PASS: cycle162 resilience/policy service optimistic-concurrency update defects fixed and retested\n";
